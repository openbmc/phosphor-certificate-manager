#include "x509_utils.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl3.h>
#include <openssl/x509_vfy.h>

#include <cstdio>
#include <ctime>
#include <exception>
#include <memory>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor::certs
{

namespace
{

using ::phosphor::logging::elog;
using ::phosphor::logging::entry;
using ::phosphor::logging::level;
using ::phosphor::logging::log;
using ::sdbusplus::xyz::openbmc_project::Certs::Error::InvalidCertificate;
using ::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using Reason = ::phosphor::logging::xyz::openbmc_project::Certs::
    InvalidCertificate::REASON;

// RAII support for openSSL functions.
using X509StorePtr = std::unique_ptr<X509_STORE, decltype(&::X509_STORE_free)>;
using X509StoreCtxPtr =
    std::unique_ptr<X509_STORE_CTX, decltype(&::X509_STORE_CTX_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&::X509_free)>;
using BIOMemPtr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using ASN1TimePtr = std::unique_ptr<ASN1_TIME, decltype(&ASN1_STRING_free)>;
using SSLCtxPtr = std::unique_ptr<SSL_CTX, decltype(&::SSL_CTX_free)>;

// Trust chain related errors.`
constexpr bool isTrustChainError(int error)
{
    return error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
           error == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ||
           error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
           error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT ||
           error == X509_V_ERR_CERT_UNTRUSTED ||
           error == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE;
}
} // namespace

X509StorePtr getX509Store(const std::string& certSrcPath)
{
    // Create an empty X509_STORE structure for certificate validation.
    X509StorePtr x509Store(X509_STORE_new(), &X509_STORE_free);
    if (!x509Store)
    {
        log<level::ERR>("Error occurred during X509_STORE_new call");
        elog<InternalFailure>();
    }

    OpenSSL_add_all_algorithms();

    // ADD Certificate Lookup method.
    // lookup will be cleaned up automatically when the holding Store goes away.
    auto lookup = X509_STORE_add_lookup(x509Store.get(), X509_LOOKUP_file());

    if (!lookup)
    {
        log<level::ERR>("Error occurred during X509_STORE_add_lookup call");
        elog<InternalFailure>();
    }
    // Load the Certificate file into X509 Store.
    if (int errCode = X509_LOOKUP_load_file(lookup, certSrcPath.c_str(),
                                            X509_FILETYPE_PEM);
        errCode != 1)
    {
        log<level::ERR>("Error occurred during X509_LOOKUP_load_file call",
                        entry("FILE=%s", certSrcPath.c_str()));
        elog<InvalidCertificate>(Reason("Invalid certificate file format"));
    }
    return x509Store;
}

X509Ptr loadCert(const std::string& filePath)
{
    // Read Certificate file
    X509Ptr cert(X509_new(), ::X509_free);
    if (!cert)
    {
        log<level::ERR>("Error occurred during X509_new call",
                        entry("FILE=%s", filePath.c_str()),
                        entry("ERRCODE=%lu", ERR_get_error()));
        elog<InternalFailure>();
    }

    BIOMemPtr bioCert(BIO_new_file(filePath.c_str(), "rb"), ::BIO_free);
    if (!bioCert)
    {
        log<level::ERR>("Error occurred during BIO_new_file call",
                        entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }

    X509* x509 = cert.get();
    if (!PEM_read_bio_X509(bioCert.get(), &x509, nullptr, nullptr))
    {
        log<level::ERR>("Error occurred during PEM_read_bio_X509 call",
                        entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }
    return cert;
}

// Checks that notBefore is not earlier than the unix epoch given that
// the corresponding DBus interface is uint64_t.
void validateCertificateStartDate(X509& cert)
{
    int days = 0;
    int secs = 0;

    ASN1TimePtr epoch(ASN1_TIME_new(), ASN1_STRING_free);
    // Set time to 00:00am GMT, Jan 1 1970; format: YYYYMMDDHHMMSSZ
    ASN1_TIME_set_string(epoch.get(), "19700101000000Z");

    ASN1_TIME* notBefore = X509_get_notBefore(&cert);
    ASN1_TIME_diff(&days, &secs, epoch.get(), notBefore);

    if (days < 0 || secs < 0)
    {
        log<level::ERR>("Certificate valid date starts before the Unix Epoch");
        elog<InvalidCertificate>(
            Reason("NotBefore should after 19700101000000Z"));
    }
}

void validateCertificateAgainstStore(X509_STORE& x509Store, X509& cert)
{
    int errCode = X509_V_OK;
    X509StoreCtxPtr storeCtx(X509_STORE_CTX_new(), ::X509_STORE_CTX_free);
    if (!storeCtx)
    {
        log<level::ERR>("Error occurred during X509_STORE_CTX_new call");
        elog<InternalFailure>();
    }

    errCode = X509_STORE_CTX_init(storeCtx.get(), &x509Store, &cert, nullptr);
    if (errCode != 1)
    {
        log<level::ERR>("Error occurred during X509_STORE_CTX_init call");
        elog<InternalFailure>();
    }

    // Set time to current time.
    auto locTime = time(nullptr);

    X509_STORE_CTX_set_time(storeCtx.get(), X509_V_FLAG_USE_CHECK_TIME,
                            locTime);

    errCode = X509_verify_cert(storeCtx.get());
    if (errCode == 1)
    {
        errCode = X509_V_OK;
    }
    else if (errCode == 0)
    {
        errCode = X509_STORE_CTX_get_error(storeCtx.get());
        log<level::INFO>(
            "Error occurred during X509_verify_cert call, checking for known "
            "error",
            entry("ERRCODE=%d", errCode),
            entry("ERROR_STR=%s", X509_verify_cert_error_string(errCode)));
    }
    else
    {
        log<level::ERR>("Error occurred during X509_verify_cert call");
        elog<InternalFailure>();
    }

    // Allow certificate upload, for "certificate is not yet valid" and
    // trust chain related errors.
    if (!((errCode == X509_V_OK) ||
          (errCode == X509_V_ERR_CERT_NOT_YET_VALID) ||
          isTrustChainError(errCode)))
    {
        if (errCode == X509_V_ERR_CERT_HAS_EXPIRED)
        {
            log<level::ERR>("Expired certificate ");
            elog<InvalidCertificate>(Reason("Expired Certificate"));
        }
        // Loging general error here.
        log<level::ERR>(
            "Certificate validation failed", entry("ERRCODE=%d", errCode),
            entry("ERROR_STR=%s", X509_verify_cert_error_string(errCode)));
        elog<InvalidCertificate>(Reason("Certificate validation failed"));
    }
}

void validateCertificateInSSLContext(X509& cert)
{
    const SSL_METHOD* method = TLS_method();
    SSLCtxPtr ctx(SSL_CTX_new(method), SSL_CTX_free);
    if (SSL_CTX_use_certificate(ctx.get(), &cert) != 1)
    {
        log<level::ERR>("Certificate is not usable",
                        entry("ERRCODE=%x", ERR_get_error()));
        elog<InvalidCertificate>(Reason("Certificate is not usable"));
    }
}

std::string generateCertId(X509& cert)
{
    unsigned long subjectNameHash = X509_subject_name_hash(&cert);
    unsigned long issuerSerialHash = X509_issuer_and_serial_hash(&cert);
    static constexpr auto CERT_ID_LENGTH = 17;
    char idBuff[CERT_ID_LENGTH];

    snprintf(idBuff, CERT_ID_LENGTH, "%08lx%08lx", subjectNameHash,
             issuerSerialHash);

    return {idBuff};
}

std::unique_ptr<X509, decltype(&::X509_free)> parseCert(const std::string& pem)
{
    if (pem.size() > INT_MAX)
    {
        log<level::ERR>("Error occurred during parseCert: PEM is too long");
        elog<InvalidCertificate>(Reason("Invalid PEM: too long"));
    }
    X509Ptr cert(X509_new(), ::X509_free);
    if (!cert)
    {
        log<level::ERR>("Error occurred during X509_new call",
                        entry("ERRCODE=%lu", ERR_get_error()));
        elog<InternalFailure>();
    }

    BIOMemPtr bioCert(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())),
                      ::BIO_free);
    X509* x509 = cert.get();
    if (!PEM_read_bio_X509(bioCert.get(), &x509, nullptr, nullptr))
    {
        log<level::ERR>("Error occurred during PEM_read_bio_X509 call",
                        entry("PEM=%s", pem.c_str()));
        elog<InternalFailure>();
    }
    return cert;
}
} // namespace phosphor::certs
