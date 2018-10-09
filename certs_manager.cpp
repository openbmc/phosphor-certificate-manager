#include "certs_manager.hpp"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <experimental/filesystem>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
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

namespace fs = std::experimental::filesystem;
using namespace phosphor::logging;
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

void Manager::install(const std::string path)
{
    // Verify the certificate file
    auto rc = verifyCert(path);
    // Allow certificate upload, for "certificate is not yet valid" and
    // trust chain related errors.
    if (!((rc == X509_V_OK) || (rc == X509_V_ERR_CERT_NOT_YET_VALID) ||
          TRUST_CHAIN_ERR(rc)))
    {
        if (rc == X509_V_ERR_CERT_HAS_EXPIRED)
        {
            elog<InvalidCertificate>(Reason("Expired Certificate"));
        }
        // Loging general error here.
        elog<InvalidCertificate>(Reason("Certificate validation failed"));
    }

    // Invoke type specific install function.
    auto iter = typeFuncMap.find(type);
    if (iter == typeFuncMap.end())
    {
        log<level::ERR>("Unsupported Type", entry("TYPE=%s", type.c_str()));
        elog<InternalFailure>();
    }
    iter->second(path);

    // Copy the certificate file
    copy(path, certPath);

    if (!unit.empty())
    {
        reloadOrReset(unit);
    }
}

void Manager::serverInstallHelper(const std::string& filePath)
{
    if (!compareKeys(filePath))
    {
        elog<InvalidCertificate>(
            Reason("Private key is not matching with Certificate"));
    }
}

void Manager::clientInstallHelper(const std::string& filePath)
{
    if (!compareKeys(filePath))
    {
        elog<InvalidCertificate>(
            Reason("Private key is not matching with Certificate"));
    }
}

void Manager::authorityInstallHelper(const std::string& filePath)
{
    // No additional steps required now.
}

void Manager::reloadOrReset(const std::string& unit)
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

void Manager::copy(const std::string& src, const std::string& dst)
{
    try
    {
        auto path = fs::path(dst).parent_path();
        // create dst path folder by default
        fs::create_directories(path);
        fs::copy_file(src, dst, fs::copy_options::overwrite_existing);
    }
    catch (fs::filesystem_error& e)
    {
        log<level::ERR>("Failed to copy certificate", entry("ERR=%s", e.what()),
                        entry("SRC=%s", src.c_str()),
                        entry("DST=%s", dst.c_str()));
        elog<InternalFailure>();
    }
}

X509_Ptr Manager::loadCert(const std::string& filePath)
{
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

int32_t Manager::verifyCert(const std::string& filePath)
{
    auto errCode = X509_V_OK;

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
    int32_t rc = X509_LOOKUP_load_file(lookup.get(), filePath.c_str(),
                                       X509_FILETYPE_PEM);
    if (rc != 1)
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

    rc = X509_STORE_CTX_init(storeCtx.get(), x509Store, cert.get(), NULL);
    if (rc != 1)
    {
        log<level::ERR>("Error occured during X509_STORE_CTX_init call",
                        entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }

    // Set time to current time.
    auto locTime = time(nullptr);

    X509_STORE_CTX_set_time(storeCtx.get(), X509_V_FLAG_USE_CHECK_TIME,
                            locTime);

    rc = X509_verify_cert(storeCtx.get());
    if (rc == 1)
    {
        errCode = X509_V_OK;
    }
    else if (rc == 0)
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
    return errCode;
}

bool Manager::compareKeys(const std::string& filePath)
{
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

void Manager::delete_()
{
    try
    {
        if (!fs::remove(certPath))
        {
            log<level::INFO>("Certificate file not found!",
                             entry("PATH=%s", certPath.c_str()));
        }
        else
        {
            reloadOrReset(unit);
        }
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(
            "Failed to delete certificate", entry("UNIT=%s", unit.c_str()),
            entry("ERR=%s", e.what()), entry("PATH=%s", certPath.c_str()));
        elog<InternalFailure>();
    }
}

} // namespace certs
} // namespace phosphor
