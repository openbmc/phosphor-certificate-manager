#include "config.h"

#include "x509_utils.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl3.h>
#include <openssl/x509_vfy.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <cstdio>
#include <ctime>
#include <exception>
#include <memory>

namespace phosphor::certs
{

namespace
{

using ::phosphor::logging::elog;
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
using EVPPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;

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
        lg2::error("Error occurred during X509_STORE_new call");
        elog<InternalFailure>();
    }

    OpenSSL_add_all_algorithms();

    // ADD Certificate Lookup method.
    // lookup will be cleaned up automatically when the holding Store goes away.
    auto lookup = X509_STORE_add_lookup(x509Store.get(), X509_LOOKUP_file());

    if (!lookup)
    {
        lg2::error("Error occurred during X509_STORE_add_lookup call");
        elog<InternalFailure>();
    }
    // Load the Certificate file into X509 Store.
    if (int errCode = X509_LOOKUP_load_file(lookup, certSrcPath.c_str(),
                                            X509_FILETYPE_PEM);
        errCode != 1)
    {
        lg2::error(
            "Error occurred during X509_LOOKUP_load_file call, FILE:{FILE}",
            "FILE", certSrcPath);
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
        lg2::error(
            "Error occurred during X509_new call, FILE:{FILE}, ERRCODE:{ERRCODE}",
            "FILE", filePath, "ERRCODE", ERR_get_error());
        elog<InternalFailure>();
    }

    BIOMemPtr bioCert(BIO_new_file(filePath.c_str(), "rb"), ::BIO_free);
    if (!bioCert)
    {
        lg2::error("Error occurred during BIO_new_file call, FILE:{FILE}",
                   "FILE", filePath);
        elog<InternalFailure>();
    }

    X509* x509 = cert.get();
    if (!PEM_read_bio_X509(bioCert.get(), &x509, nullptr, nullptr))
    {
        lg2::error("Error occurred during PEM_read_bio_X509 call, FILE:{FILE}",
                   "FILE", filePath);
        elog<InternalFailure>();
    }
    return cert;
}

int validateCertificateKeyType(X509& cert)
{
    EVPPkeyPtr pubKey(X509_get_pubkey(&cert), ::EVP_PKEY_free);
    if (!pubKey)
    {
        lg2::error("X509_get_pubkey() failed, ERRCODE:{ERRCODE}", "ERRCODE",
                   ERR_get_error());
        elog<InvalidCertificate>(Reason("Failed to get public key info"));
    }
    int keyType = EVP_PKEY_id(pubKey.get());
    int pkeyType = EVP_PKEY_type(keyType);
    lg2::info("Certificate cryptographic keyType, KEYTYPE:{KEYTYPE}", "KEYTYPE",
              pkeyType);
    return pkeyType;
}
void validateCertificateKeyLength(X509& cert)
{
    EVPPkeyPtr pubKey(X509_get_pubkey(&cert), ::EVP_PKEY_free);
    if (!pubKey)
    {
        lg2::error("X509_get_pubkey() failed, ERRCODE:{ERRCODE}", "ERRCODE",
                   ERR_get_error());
        elog<InvalidCertificate>(Reason("Failed to get public key info"));
    }
    int minKeyBitLength = 0;
    int maxKeyBitLength = 0;
    int keyLen = EVP_PKEY_bits(pubKey.get());
    int pkeyType = validateCertificateKeyType(cert);
    if ((pkeyType == EVP_PKEY_RSA) || (pkeyType == EVP_PKEY_RSA2))
    {
        minKeyBitLength = 2048;
        maxKeyBitLength = 4096;
    }
    else if (pkeyType == EVP_PKEY_EC)
    {
        minKeyBitLength = 384;
        maxKeyBitLength = 512;
    }
    else
    {
        lg2::error(
            "Invalid cryptographic KeyType certificate uploaded, KEYTYPE:{KEYTYPE}",
            "KEYTYPE", pkeyType);
        elog<InvalidCertificate>(Reason("Invalid key type certificate"));
    }
    lg2::info("Certificate cryptographic length, KEYLENGTH:{KEYLENGTH}",
              "KEYLENGTH", keyLen);
    if (keyLen < minKeyBitLength || keyLen > maxKeyBitLength)
    {
        lg2::error(
            "Invalid cryptographic length certificate uploaded, KEYLENGTH:{KEYLENGTH}",
            "KEYLENGTH", keyLen);
        elog<InvalidCertificate>(Reason("Invalid key length certificate"));
    }
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
        lg2::error("Certificate valid date starts before the Unix Epoch");
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
        lg2::error("Error occurred during X509_STORE_CTX_new call");
        elog<InternalFailure>();
    }

    errCode = X509_STORE_CTX_init(storeCtx.get(), &x509Store, &cert, nullptr);
    if (errCode != 1)
    {
        lg2::error("Error occurred during X509_STORE_CTX_init call");
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
        lg2::info(
            "Error occurred during X509_verify_cert call, checking for known "
            "error, ERRCODE:{ERRCODE}, ERROR_STR:{ERROR_STR}",
            "ERRCODE", errCode, "ERROR_STR",
            X509_verify_cert_error_string(errCode));
    }
    else
    {
        lg2::error("Error occurred during X509_verify_cert call");
        elog<InternalFailure>();
    }

    // Allow certificate upload, for "certificate is not yet valid" and
    // trust chain related errors.
    // If ALLOW_EXPIRED is defined, allow expired certificate so that it
    // could be replaced
    bool isOK = (errCode == X509_V_OK) ||
                (errCode == X509_V_ERR_CERT_NOT_YET_VALID) ||
                isTrustChainError(errCode) ||
                (allowExpired && errCode == X509_V_ERR_CERT_HAS_EXPIRED);

    if (!isOK)
    {
        if (errCode == X509_V_ERR_CERT_HAS_EXPIRED)
        {
            lg2::error("Expired certificate ");
            elog<InvalidCertificate>(Reason("Expired Certificate"));
        }
        // Logging general error here.
        lg2::error(
            "Certificate validation failed, ERRCODE:{ERRCODE}, ERROR_STR:{ERROR_STR}",
            "ERRCODE", errCode, "ERROR_STR",
            X509_verify_cert_error_string(errCode));
        elog<InvalidCertificate>(Reason("Certificate validation failed"));
    }
}

void validateCertificateInSSLContext(X509& cert)
{
    const SSL_METHOD* method = TLS_method();
    SSLCtxPtr ctx(SSL_CTX_new(method), SSL_CTX_free);
    if (SSL_CTX_use_certificate(ctx.get(), &cert) != 1)
    {
        lg2::error("Certificate is not usable, ERRCODE:{ERRCODE}", "ERRCODE",
                   ERR_get_error());
        elog<InvalidCertificate>(Reason("Certificate is not usable"));
    }
}

std::string generateCertId(X509& cert)
{
    unsigned long subjectNameHash = X509_subject_name_hash(&cert);
    unsigned long issuerSerialHash = X509_issuer_and_serial_hash(&cert);
    static constexpr auto certIdLength = 17;
    char idBuff[certIdLength];

    snprintf(idBuff, certIdLength, "%08lx%08lx", subjectNameHash,
             issuerSerialHash);

    return {idBuff};
}

std::unique_ptr<X509, decltype(&::X509_free)> parseCert(const std::string& pem)
{
    if (pem.size() > INT_MAX)
    {
        lg2::error("Error occurred during parseCert: PEM is too long");
        elog<InvalidCertificate>(Reason("Invalid PEM: too long"));
    }
    X509Ptr cert(X509_new(), ::X509_free);
    if (!cert)
    {
        lg2::error("Error occurred during X509_new call, ERRCODE:{ERRCODE}",
                   "ERRCODE", ERR_get_error());
        elog<InternalFailure>();
    }

    BIOMemPtr bioCert(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())),
                      ::BIO_free);
    X509* x509 = cert.get();
    if (!PEM_read_bio_X509(bioCert.get(), &x509, nullptr, nullptr))
    {
        lg2::error("Error occurred during PEM_read_bio_X509 call, PEM:{PEM}",
                   "PEM", pem);
        elog<InternalFailure>();
    }
    return cert;
}
} // namespace phosphor::certs
