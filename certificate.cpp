#include "certificate.hpp"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <xyz/openbmc_project/Certs/Install/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace certs
{
// RAII support for openSSL functions.
using BIO_MEM_Ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using X509_STORE_CTX_Ptr =
    std::unique_ptr<X509_STORE_CTX, decltype(&::X509_STORE_CTX_free)>;
using X509_LOOKUP_Ptr =
    std::unique_ptr<X509_LOOKUP, decltype(&::X509_LOOKUP_free)>;
using EVP_PKEY_Ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BUF_MEM_Ptr = std::unique_ptr<BUF_MEM, decltype(&::BUF_MEM_free)>;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidCertificate =
    sdbusplus::xyz::openbmc_project::Certs::Install::Error::InvalidCertificate;
using Reason = xyz::openbmc_project::Certs::Install::InvalidCertificate::REASON;

// Trust chain related errors.`
#define TRUST_CHAIN_ERR(errnum)                                                \
    ((errnum == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ||                     \
     (errnum == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) ||                       \
     (errnum == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) ||               \
     (errnum == X509_V_ERR_CERT_UNTRUSTED) ||                                  \
     (errnum == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE))

Certificate::Certificate(sdbusplus::bus::bus& bus, const std::string& objPath,
                         const CertificateType& type,
                         const UnitsToRestart& unit,
                         const CertInstallPath& installPath,
                         const CertUploadPath& uploadPath) :
    bus(bus), objectPath(objPath), certType(type), unitToRestart(unit),
    certInstallPath(installPath)
{
    auto installHelper = [this](const auto& filePath) {
        if (!compareKeys(filePath))
        {
            elog<InvalidCertificate>(
                Reason("Private key does not match the Certificate"));
        };
    };
    typeFuncMap[SERVER] = installHelper;
    typeFuncMap[CLIENT] = installHelper;
    typeFuncMap[AUTHORITY] = [](auto filePath) {};

    install(uploadPath);
}

Certificate::~Certificate()
{
    if (!fs::remove(certInstallPath))
    {
        log<level::INFO>("Certificate file not found!",
                         entry("PATH=%s", certInstallPath.c_str()));
    }
    else if (!unitToRestart.empty())
    {
        reloadOrReset(unitToRestart);
    }
}

void Certificate::install(const std::string filePath)
{
    log<level::INFO>("Certificate install ",
                     entry("FILEPATH=%s", filePath.c_str()));
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
        // Log Error message
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
        log<level::ERR>("Certificate verification failed",
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
        // Loging general error here.
        elog<InvalidCertificate>(Reason("Certificate validation failed"));
    }

    // Invoke type specific compare keys function.
    auto iter = typeFuncMap.find(certType);
    if (iter == typeFuncMap.end())
    {
        log<level::ERR>("Unsupported Type", entry("TYPE=%s", certType.c_str()));
        elog<InternalFailure>();
    }
    iter->second(filePath);

    // Copy thecertificate to the installation path
    auto path = fs::path(certInstallPath).parent_path();
    try
    {
        fs::create_directories(path);
        // During bootup will be parsing existing file so no need to
        // copy it.
        if (filePath != certInstallPath)
        {
            fs::copy_file(filePath, certInstallPath,
                          fs::copy_options::overwrite_existing);
        }
    }
    catch (fs::filesystem_error& e)
    {
        log<level::ERR>("Failed to copy certificate", entry("ERR=%s", e.what()),
                        entry("SRC=%s", filePath.c_str()),
                        entry("DST=%s", certInstallPath.c_str()));
        elog<InternalFailure>();
    }
}

bool Certificate::compareKeys(const std::string& filePath)
{
    log<level::INFO>("Certificate compareKeys",
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
        return false;
    }
    return true;
}

void Certificate::reloadOrReset(const UnitsToRestart& unit)
{
    constexpr auto SYSTEMD_SERVICE = "org.freedesktop.systemd1";
    constexpr auto SYSTEMD_OBJ_PATH = "/org/freedesktop/systemd1";
    constexpr auto SYSTEMD_INTERFACE = "org.freedesktop.systemd1.Manager";

    try
    {
        auto method =
            bus.new_method_call(SYSTEMD_SERVICE, SYSTEMD_OBJ_PATH,
                                SYSTEMD_INTERFACE, "ReloadOrRestartUnit");
        method.append(unit, "replace");
        bus.call_noreply(method);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>("Failed to reload or restart service",
                        entry("ERR=%s", e.what()),
                        entry("UNIT=%s", unit.c_str()));
        elog<InternalFailure>();
    }
}
} // namespace certs
} // namespace phosphor
