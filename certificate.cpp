#include "config.h"

#include "certificate.hpp"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <xyz/openbmc_project/Certs/error.hpp>
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
using ASN1_TIME_ptr = std::unique_ptr<ASN1_TIME, decltype(&ASN1_STRING_free)>;
using EVP_PKEY_Ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BUF_MEM_Ptr = std::unique_ptr<BUF_MEM, decltype(&::BUF_MEM_free)>;
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

// Refer to schema 2018.3
// http://redfish.dmtf.org/schemas/v1/Certificate.json#/definitions/KeyUsage for
// supported KeyUsage types in redfish
// Refer to
// https://github.com/openssl/openssl/blob/master/include/openssl/x509v3.h for
// key usage bit fields
std::map<uint8_t, std::string> keyUsageToRfStr = {
    {KU_DIGITAL_SIGNATURE, "DigitalSignature"},
    {KU_NON_REPUDIATION, "NonRepudiation"},
    {KU_KEY_ENCIPHERMENT, "KeyEncipherment"},
    {KU_DATA_ENCIPHERMENT, "DataEncipherment"},
    {KU_KEY_AGREEMENT, "KeyAgreement"},
    {KU_KEY_CERT_SIGN, "KeyCertSign"},
    {KU_CRL_SIGN, "CRLSigning"},
    {KU_ENCIPHER_ONLY, "EncipherOnly"},
    {KU_DECIPHER_ONLY, "DecipherOnly"}};

// Refer to schema 2018.3
// http://redfish.dmtf.org/schemas/v1/Certificate.json#/definitions/KeyUsage for
// supported Extended KeyUsage types in redfish
std::map<uint8_t, std::string> extendedKeyUsageToRfStr = {
    {NID_server_auth, "ServerAuthentication"},
    {NID_client_auth, "ClientAuthentication"},
    {NID_email_protect, "EmailProtection"},
    {NID_OCSP_sign, "OCSPSigning"},
    {NID_ad_timeStamping, "Timestamping"},
    {NID_code_sign, "CodeSigning"}};

Certificate::Certificate(sdbusplus::bus::bus& bus, const std::string& objPath,
                         const CertificateType& type,
                         const UnitsToRestart& unit,
                         const CertInstallPath& installPath,
                         const CertUploadPath& uploadPath,
                         bool isSkipUnitReload,
                         const CertWatchPtr& certWatchPtr) :
    CertIfaces(bus, objPath.c_str(), true),
    bus(bus), objectPath(objPath), certType(type), unitToRestart(unit),
    certInstallPath(installPath), certWatchPtr(certWatchPtr)
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

    auto appendPrivateKey = [this](const std::string& filePath) {
        checkAndAppendPrivateKey(filePath);
    };

    appendKeyMap[SERVER] = appendPrivateKey;
    appendKeyMap[CLIENT] = appendPrivateKey;
    appendKeyMap[AUTHORITY] = [](const std::string& filePath) {};

    // install the certificate
    install(uploadPath, isSkipUnitReload);

    this->emit_object_added();
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

void Certificate::replace(const std::string filePath)
{
    install(filePath, false);
}

void Certificate::install(const std::string& filePath, bool isSkipUnitReload)
{
    log<level::INFO>("Certificate install ",
                     entry("FILEPATH=%s", filePath.c_str()));
    auto errCode = X509_V_OK;

    // stop watch for user initiated certificate install
    if (certWatchPtr)
    {
        certWatchPtr->stopWatch();
    }

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
        log<level::INFO>(
            "Error occured during X509_verify_cert call, checking for known "
            "error",
            entry("FILE=%s", filePath.c_str()), entry("ERRCODE=%d", errCode),
            entry("ERROR_STR=%s", X509_verify_cert_error_string(errCode)));
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

    // Invoke type specific append private key function.
    auto appendIter = appendKeyMap.find(certType);
    if (appendIter == appendKeyMap.end())
    {
        log<level::ERR>("Unsupported Type", entry("TYPE=%s", certType.c_str()));
        elog<InternalFailure>();
    }
    appendIter->second(filePath);

    // Invoke type specific compare keys function.
    auto compIter = typeFuncMap.find(certType);
    if (compIter == typeFuncMap.end())
    {
        log<level::ERR>("Unsupported Type", entry("TYPE=%s", certType.c_str()));
        elog<InternalFailure>();
    }
    compIter->second(filePath);

    // Copy the certificate to the installation path
    // During bootup will be parsing existing file so no need to
    // copy it.
    if (filePath != certInstallPath)
    {
        std::ifstream inputCertFileStream;
        std::ofstream outputCertFileStream;
        inputCertFileStream.exceptions(std::ifstream::failbit |
                                       std::ifstream::badbit |
                                       std::ifstream::eofbit);
        outputCertFileStream.exceptions(std::ofstream::failbit |
                                        std::ofstream::badbit |
                                        std::ofstream::eofbit);
        try
        {
            inputCertFileStream.open(filePath);
            outputCertFileStream.open(certInstallPath, std::ios::out);
            outputCertFileStream << inputCertFileStream.rdbuf() << std::flush;
            inputCertFileStream.close();
            outputCertFileStream.close();
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Failed to copy certificate",
                            entry("ERR=%s", e.what()),
                            entry("SRC=%s", filePath.c_str()),
                            entry("DST=%s", certInstallPath.c_str()));
            elog<InternalFailure>();
        }
    }

    if (!isSkipUnitReload)
    {
        // restart the units
        if (!unitToRestart.empty())
        {
            reloadOrReset(unitToRestart);
        }
    }

    // Parse the certificate file and populate properties
    populateProperties();

    // restart watch
    if (certWatchPtr)
    {
        certWatchPtr->startWatch();
    }
}

void Certificate::populateProperties()
{
    X509_Ptr cert = std::move(loadCert(certInstallPath));
    // Update properties if no error thrown
    BIO_MEM_Ptr certBio(BIO_new(BIO_s_mem()), BIO_free);
    PEM_write_bio_X509(certBio.get(), cert.get());
    BUF_MEM_Ptr certBuf(BUF_MEM_new(), BUF_MEM_free);
    BUF_MEM* buf = certBuf.get();
    BIO_get_mem_ptr(certBio.get(), &buf);
    std::string certStr(buf->data, buf->length);
    CertificateIface::certificateString(certStr);

    static const int maxKeySize = 4096;
    char subBuffer[maxKeySize] = {0};
    BIO_MEM_Ptr subBio(BIO_new(BIO_s_mem()), BIO_free);
    // This pointer cannot be freed independantly.
    X509_NAME* sub = X509_get_subject_name(cert.get());
    X509_NAME_print_ex(subBio.get(), sub, 0, XN_FLAG_SEP_COMMA_PLUS);
    BIO_read(subBio.get(), subBuffer, maxKeySize);
    CertificateIface::subject(subBuffer);

    char issuerBuffer[maxKeySize] = {0};
    BIO_MEM_Ptr issuerBio(BIO_new(BIO_s_mem()), BIO_free);
    // This pointer cannot be freed independantly.
    X509_NAME* issuer_name = X509_get_issuer_name(cert.get());
    X509_NAME_print_ex(issuerBio.get(), issuer_name, 0, XN_FLAG_SEP_COMMA_PLUS);
    BIO_read(issuerBio.get(), issuerBuffer, maxKeySize);
    CertificateIface::issuer(issuerBuffer);

    std::vector<std::string> keyUsageList;
    ASN1_BIT_STRING* usage;

    // Go through each usage in the bit string and convert to
    // corresponding string value
    if ((usage = static_cast<ASN1_BIT_STRING*>(
             X509_get_ext_d2i(cert.get(), NID_key_usage, NULL, NULL))))
    {
        for (auto i = 0; i < usage->length; ++i)
        {
            for (auto& x : keyUsageToRfStr)
            {
                if (x.first & usage->data[i])
                {
                    keyUsageList.push_back(x.second);
                    break;
                }
            }
        }
    }

    EXTENDED_KEY_USAGE* extUsage;
    if ((extUsage = static_cast<EXTENDED_KEY_USAGE*>(
             X509_get_ext_d2i(cert.get(), NID_ext_key_usage, NULL, NULL))))
    {
        for (int i = 0; i < sk_ASN1_OBJECT_num(extUsage); i++)
        {
            keyUsageList.push_back(extendedKeyUsageToRfStr[OBJ_obj2nid(
                sk_ASN1_OBJECT_value(extUsage, i))]);
        }
    }
    CertificateIface::keyUsage(keyUsageList);

    int days = 0;
    int secs = 0;

    ASN1_TIME_ptr epoch(ASN1_TIME_new(), ASN1_STRING_free);
    // Set time to 12:00am GMT, Jan 1 1970
    ASN1_TIME_set_string(epoch.get(), "700101120000Z");

    static const int dayToSeconds = 24 * 60 * 60;
    ASN1_TIME* notAfter = X509_get_notAfter(cert.get());
    ASN1_TIME_diff(&days, &secs, epoch.get(), notAfter);
    CertificateIface::validNotAfter((days * dayToSeconds) + secs);

    ASN1_TIME* notBefore = X509_get_notBefore(cert.get());
    ASN1_TIME_diff(&days, &secs, epoch.get(), notBefore);
    CertificateIface::validNotBefore((days * dayToSeconds) + secs);
}

X509_Ptr Certificate::loadCert(const std::string& filePath)
{
    log<level::INFO>("Certificate loadCert",
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

void Certificate::checkAndAppendPrivateKey(const std::string& filePath)
{
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
        fs::path privateKeyFile = fs::path(certInstallPath).parent_path();
        privateKeyFile = privateKeyFile / PRIV_KEY_FILE_NAME;
        if (!fs::exists(privateKeyFile))
        {
            log<level::ERR>("Private key file is not found",
                            entry("FILE=%s", privateKeyFile.c_str()));
            elog<InternalFailure>();
        }

        std::ifstream privKeyFileStream;
        std::ofstream certFileStream;
        privKeyFileStream.exceptions(std::ifstream::failbit |
                                     std::ifstream::badbit |
                                     std::ifstream::eofbit);
        certFileStream.exceptions(std::ofstream::failbit |
                                  std::ofstream::badbit |
                                  std::ofstream::eofbit);
        try
        {
            privKeyFileStream.open(privateKeyFile);
            certFileStream.open(filePath, std::ios::app);
            certFileStream << std::endl; // insert line break
            certFileStream << privKeyFileStream.rdbuf() << std::flush;
            privKeyFileStream.close();
            certFileStream.close();
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Failed to append private key",
                            entry("ERR=%s", e.what()),
                            entry("SRC=%s", privateKeyFile.c_str()),
                            entry("DST=%s", filePath.c_str()));
            elog<InternalFailure>();
        }
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
