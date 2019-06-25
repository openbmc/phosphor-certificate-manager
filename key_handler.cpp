#include "config.h"

#include "key_handler.hpp"

#include <openssl/err.h>
#include <openssl/pem.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <phosphor-logging/elog-errors.hpp>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace certs
{
using namespace phosphor::logging;
namespace fs = std::filesystem;

// RAII support for openSSL functions.
using BIO_MEM_Ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using EVP_PKEY_Ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidCertificate =
    sdbusplus::xyz::openbmc_project::Certs::Error::InvalidCertificate;
using Reason = xyz::openbmc_project::Certs::InvalidCertificate::REASON;

// Trust chain related errors.`
#define TRUST_CHAIN_ERR(errnum)                                                \
    ((errnum == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ||                     \
     (errnum == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) ||                       \
     (errnum == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) ||               \
     (errnum == X509_V_ERR_CERT_UNTRUSTED) ||                                  \
     (errnum == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE))

KeyHandler::KeyHandler(const CertType& certType) : certType(certType)
{
    auto compareKeys = [this](const std::string& filePath) {
        this->compareKeys(filePath);
    };
    compareKeyMap[SERVER] = compareKeys;
    compareKeyMap[CLIENT] = compareKeys;
    compareKeyMap[AUTHORITY] = [](const std::string& filePath) {};

    auto appendKeys = [this](const std::string& filePath) {
        this->appendPrivateKey(filePath);
    };
    appendKeyMap[SERVER] = appendKeys;
    appendKeyMap[CLIENT] = appendKeys;
    appendKeyMap[AUTHORITY] = [](const std::string& filePath) {};
}

void KeyHandler::verify(const std::string& filePath)
{
    log<level::INFO>("KeyHandler verify",
                     entry("FILEPATH=%s", filePath.c_str()));
    using X509_STORE_CTX_Ptr =
        std::unique_ptr<X509_STORE_CTX, decltype(&::X509_STORE_CTX_free)>;
    using X509_LOOKUP_Ptr =
        std::unique_ptr<X509_LOOKUP, decltype(&::X509_LOOKUP_free)>;
    auto errCode = X509_V_OK;

    // Verify the certificate file
    fs::path file(filePath);
    if (!fs::exists(file))
    {
        log<level::ERR>("File is Missing", entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }

    try
    {
        if (fs::file_size(filePath) == 0)
        {
            // file is empty
            log<level::ERR>("File is empty",
                            entry("FILE=%s", filePath.c_str()));
            elog<InvalidCertificate>(Reason("File is empty"));
        }
    }
    catch (const fs::filesystem_error& e)
    {
        log<level::ERR>(e.what(), entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }

    // Defining store object as RAW to avoid double free.
    // X509_LOOKUP_free free up store object.
    // Create an empty X509_STORE structure for certificate validation.
    auto x509Store = X509_STORE_new();
    if (!x509Store)
    {
        log<level::ERR>("Error occured during X509_STORE_new call");
        elog<InternalFailure>();
    }

    OpenSSL_add_all_algorithms();

    // ADD Certificate Lookup method.
    X509_LOOKUP_Ptr lookup(X509_STORE_add_lookup(x509Store, X509_LOOKUP_file()),
                           ::X509_LOOKUP_free);
    if (!lookup)
    {
        // Normally lookup cleanup function interanlly does X509Store cleanup
        // Free up the X509Store.
        X509_STORE_free(x509Store);
        log<level::ERR>("Error occured during X509_STORE_add_lookup call");
        elog<InternalFailure>();
    }
    // Load Certificate file.
    errCode = X509_LOOKUP_load_file(lookup.get(), filePath.c_str(),
                                    X509_FILETYPE_PEM);
    if (errCode != 1)
    {
        log<level::ERR>("Error occured during X509_LOOKUP_load_file call",
                        entry("FILE=%s", filePath.c_str()));
        elog<InvalidCertificate>(Reason("Invalid certificate file format"));
    }

    // Load Certificate file into the X509 structre.
    X509_Ptr cert = std::move(loadCert(filePath));
    X509_STORE_CTX_Ptr storeCtx(X509_STORE_CTX_new(), ::X509_STORE_CTX_free);
    if (!storeCtx)
    {
        log<level::ERR>("Error occured during X509_STORE_CTX_new call",
                        entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }

    errCode = X509_STORE_CTX_init(storeCtx.get(), x509Store, cert.get(), NULL);
    if (errCode != 1)
    {
        log<level::ERR>("Error occured during X509_STORE_CTX_init call",
                        entry("FILE=%s", filePath.c_str()));
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
        log<level::INFO>("Warning Certificate verification failed",
                         entry("FILE=%s", filePath.c_str()),
                         entry("ERRCODE=%d", errCode));
    }
    else
    {
        log<level::ERR>("Error occured during X509_verify_cert call",
                        entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }

    // Allow certificate upload, for "certificate is not yet valid" and
    // trust chain related errors.
    if (!((errCode == X509_V_OK) ||
          (errCode == X509_V_ERR_CERT_NOT_YET_VALID) ||
          TRUST_CHAIN_ERR(errCode)))
    {
        if (errCode == X509_V_ERR_CERT_HAS_EXPIRED)
        {
            elog<InvalidCertificate>(Reason("Expired Certificate"));
        }
        else
        {
            // Loging general error here.
            elog<InvalidCertificate>(Reason("Certificate validation failed"));
        }
    }

    // append private key from system if not existing
    auto iter = appendKeyMap.find(certType);
    if (iter == appendKeyMap.end())
    {
        log<level::ERR>("Unsupported Type", entry("TYPE=%s", certType.c_str()));
        elog<InternalFailure>();
    }
    iter->second(filePath);

    // compare private and public key file
    iter = compareKeyMap.find(certType);
    if (iter == compareKeyMap.end())
    {
        log<level::ERR>("Unsupported Type", entry("TYPE=%s", certType.c_str()));
        elog<InternalFailure>();
    }
    iter->second(filePath);
}

X509_Ptr KeyHandler::loadCert(const std::string& filePath)
{
    log<level::INFO>("KeyHandler loadCert",
                     entry("FILEPATH=%s", filePath.c_str()));
    // Read Certificate file
    X509_Ptr cert(X509_new(), ::X509_free);
    if (!cert)
    {
        log<level::ERR>("Error occured during X509_new call",
                        entry("FILE=%s", filePath.c_str()),
                        entry("ERRCODE=%lu", ERR_get_error()));
        elog<InternalFailure>();
    }

    BIO_MEM_Ptr bioCert(BIO_new_file(filePath.c_str(), "rb"), ::BIO_free);
    if (!bioCert)
    {
        log<level::ERR>("Error occured during BIO_new_file call",
                        entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }

    X509* x509 = cert.get();
    if (!PEM_read_bio_X509(bioCert.get(), &x509, nullptr, nullptr))
    {
        log<level::ERR>("Error occured during PEM_read_bio_X509 call",
                        entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }
    return cert;
}

void KeyHandler::compareKeys(const std::string& filePath)
{
    log<level::INFO>("KeyHandler compareKeys",
                     entry("FILEPATH=%s", filePath.c_str()));
    X509_Ptr cert(X509_new(), ::X509_free);
    if (!cert)
    {
        log<level::ERR>("Error occured during X509_new call",
                        entry("FILE=%s", filePath.c_str()),
                        entry("ERRCODE=%lu", ERR_get_error()));
        elog<InternalFailure>();
    }

    BIO_MEM_Ptr bioCert(BIO_new_file(filePath.c_str(), "rb"), ::BIO_free);
    if (!bioCert)
    {
        log<level::ERR>("Error occured during BIO_new_file call",
                        entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }

    X509* x509 = cert.get();
    PEM_read_bio_X509(bioCert.get(), &x509, nullptr, nullptr);

    EVP_PKEY_Ptr pubKey(X509_get_pubkey(cert.get()), ::EVP_PKEY_free);
    if (!pubKey)
    {
        log<level::ERR>("Error occurred during X509_get_pubkey",
                        entry("FILE=%s", filePath.c_str()),
                        entry("ERRCODE=%lu", ERR_get_error()));
        elog<InvalidCertificate>(Reason("Failed to get public key info"));
    }

    BIO_MEM_Ptr keyBio(BIO_new(BIO_s_file()), ::BIO_free);
    if (!keyBio)
    {
        log<level::ERR>("Error occured during BIO_s_file call",
                        entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }
    BIO_read_filename(keyBio.get(), filePath.c_str());

    EVP_PKEY_Ptr priKey(
        PEM_read_bio_PrivateKey(keyBio.get(), nullptr, nullptr, nullptr),
        ::EVP_PKEY_free);
    if (!priKey)
    {
        log<level::ERR>("Error occurred during PEM_read_bio_PrivateKey",
                        entry("FILE=%s", filePath.c_str()),
                        entry("ERRCODE=%lu", ERR_get_error()));
        elog<InvalidCertificate>(Reason("Failed to get private key info"));
    }

    int32_t rc = EVP_PKEY_cmp(priKey.get(), pubKey.get());
    if (rc != 1)
    {
        log<level::ERR>("Private key is not matching with Certificate",
                        entry("FILE=%s", filePath.c_str()),
                        entry("ERRCODE=%d", rc));
        elog<InvalidCertificate>(
            Reason("Private key does not match the Certificate"));
    }
}

void KeyHandler::appendPrivateKey(const std::string& filePath)
{
    log<level::INFO>("KeyHandler append private key",
                     entry("FILEPATH=%s", filePath.c_str()));
    BIO_MEM_Ptr keyBio(BIO_new(BIO_s_file()), ::BIO_free);
    if (!keyBio)
    {
        log<level::ERR>("Error occured during BIO_s_file call",
                        entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }
    BIO_read_filename(keyBio.get(), filePath.c_str());

    EVP_PKEY_Ptr priKey(
        PEM_read_bio_PrivateKey(keyBio.get(), nullptr, nullptr, nullptr),
        ::EVP_PKEY_free);
    if (!priKey)
    {
        log<level::INFO>("Private key not present in file",
                         entry("FILE=%s", filePath.c_str()));
        fs::path privateKeyFile = fs::path(filePath).parent_path();
        privateKeyFile = privateKeyFile / PRIV_KEY_FILE_NAME;
        if (!fs::exists(privateKeyFile))
        {
            log<level::ERR>("Private key file is not found",
                            entry("FILE=%s", privateKeyFile.c_str()));
            elog<InternalFailure>();
        }

        std::ofstream certFileStream(filePath, std::ios::app);
        std::ifstream privKeyFileStream(privateKeyFile);
        if (!privKeyFileStream.is_open())
        {
            log<level::ERR>("Failed to open private key file",
                            entry("FILE=%s", privateKeyFile.c_str()));
            elog<InternalFailure>();
        }
        else if (!certFileStream.is_open())
        {
            log<level::ERR>("Failed to open certificate file",
                            entry("FILE=%s", filePath.c_str()));
            elog<InternalFailure>();
        }
        else
        {
            certFileStream << privKeyFileStream.rdbuf() << std::flush;
        }
    }
}

} // namespace certs
} // namespace phosphor
