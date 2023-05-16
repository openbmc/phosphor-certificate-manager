#include "config.h"

#include "certificate.hpp"

#include "certs_manager.hpp"
#include "x509_utils.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <map>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <utility>
#include <vector>
#include <watch.hpp>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor::certs
{

namespace
{
namespace fs = std::filesystem;
using ::phosphor::logging::elog;
using ::phosphor::logging::entry;
using ::phosphor::logging::level;
using ::phosphor::logging::log;
using ::phosphor::logging::report;
using InvalidCertificateError =
    ::sdbusplus::xyz::openbmc_project::Certs::Error::InvalidCertificate;
using ::phosphor::logging::xyz::openbmc_project::Certs::InvalidCertificate;
using ::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

// RAII support for openSSL functions.
using BIOMemPtr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using X509StorePtr = std::unique_ptr<X509_STORE, decltype(&::X509_STORE_free)>;
using ASN1TimePtr = std::unique_ptr<ASN1_TIME, decltype(&ASN1_STRING_free)>;
using EVPPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BufMemPtr = std::unique_ptr<BUF_MEM, decltype(&::BUF_MEM_free)>;

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

/**
 * @brief Dumps the PEM encoded certificate to installFilePath
 *
 * @param[in] pem - PEM encoded X509 certificate buffer.
 * @param[in] certFilePath - Path to the destination file.
 *
 * @return void
 */

void dumpCertificate(const std::string& pem, const std::string& certFilePath)
{
    std::ofstream outputCertFileStream;

    outputCertFileStream.exceptions(
        std::ofstream::failbit | std::ofstream::badbit | std::ofstream::eofbit);

    try
    {
        outputCertFileStream.open(certFilePath, std::ios::out);
        outputCertFileStream << pem << "\n" << std::flush;
        outputCertFileStream.close();
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to dump certificate", entry("ERR=%s", e.what()),
                        entry("SRC_PEM=%s", pem.c_str()),
                        entry("DST=%s", certFilePath.c_str()));
        elog<InternalFailure>();
    }
}
} // namespace

void Certificate::copyCertificate(const std::string& certSrcFilePath,
                                  const std::string& certFilePath)
{
    // Copy the certificate to the installation path
    // During bootup will be parsing existing file so no need to
    // copy it.
    if (certSrcFilePath != certFilePath)
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
            inputCertFileStream.open(certSrcFilePath);
            outputCertFileStream.open(certFilePath, std::ios::out);
            outputCertFileStream << inputCertFileStream.rdbuf() << std::flush;
            inputCertFileStream.close();
            outputCertFileStream.close();
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Failed to copy certificate",
                            entry("ERR=%s", e.what()),
                            entry("SRC=%s", certSrcFilePath.c_str()),
                            entry("DST=%s", certFilePath.c_str()));
            elog<InternalFailure>();
        }
    }
}

std::string
    Certificate::generateUniqueFilePath(const std::string& directoryPath)
{
    char* filePath = tempnam(directoryPath.c_str(), nullptr);
    if (filePath == nullptr)
    {
        log<level::ERR>(
            "Error occurred while creating random certificate file path",
            entry("DIR=%s", directoryPath.c_str()));
        elog<InternalFailure>();
    }
    std::string filePathStr(filePath);
    free(filePath);
    return filePathStr;
}

std::string Certificate::generateAuthCertFileX509Path(
    const std::string& certSrcFilePath, const std::string& certDstDirPath)
{
    const internal::X509Ptr cert = loadCert(certSrcFilePath);
    unsigned long hash = X509_subject_name_hash(cert.get());
    static constexpr auto certHashLength = 9;
    char hashBuf[certHashLength];

    snprintf(hashBuf, certHashLength, "%08lx", hash);

    const std::string certHash(hashBuf);
    for (size_t i = 0; i < maxNumAuthorityCertificates; ++i)
    {
        const std::string certDstFileX509Path =
            certDstDirPath + "/" + certHash + "." + std::to_string(i);
        if (!fs::exists(certDstFileX509Path))
        {
            return certDstFileX509Path;
        }
    }

    log<level::ERR>("Authority certificate x509 file path already used",
                    entry("DIR=%s", certDstDirPath.c_str()));
    elog<InternalFailure>();
}

std::string
    Certificate::generateAuthCertFilePath(const std::string& certSrcFilePath)
{
    // If there is a certificate file path (which means certificate replacement
    // is doing) use it (do not create new one)
    if (!certFilePath.empty())
    {
        return certFilePath;
    }
    // If source certificate file is located in the certificates directory use
    // it (do not create new one)
    else if (fs::path(certSrcFilePath).parent_path().string() ==
             certInstallPath)
    {
        return certSrcFilePath;
    }
    // Otherwise generate new file name/path
    else
    {
        return generateUniqueFilePath(certInstallPath);
    }
}

std::string
    Certificate::generateCertFilePath(const std::string& certSrcFilePath)
{
    if (certType == CertificateType::authority)
    {
        return generateAuthCertFilePath(certSrcFilePath);
    }
    else
    {
        return certInstallPath;
    }
}

Certificate::Certificate(sdbusplus::bus_t& bus, const std::string& objPath,
                         CertificateType type, const std::string& installPath,
                         const std::string& uploadPath, Watch* watch,
                         Manager& parent, bool restore) :
    internal::CertificateInterface(
        bus, objPath.c_str(),
        internal::CertificateInterface::action::defer_emit),
    objectPath(objPath), certType(type), certInstallPath(installPath),
    certWatch(watch), manager(parent)
{
    auto installHelper = [this](const auto& filePath) {
        if (!compareKeys(filePath))
        {
            elog<InvalidCertificateError>(InvalidCertificate::REASON(
                "Private key does not match the Certificate"));
        };
    };
    typeFuncMap[CertificateType::server] = installHelper;
    typeFuncMap[CertificateType::client] = installHelper;
    typeFuncMap[CertificateType::authority] = [](const std::string&) {};

    auto appendPrivateKey = [this](const std::string& filePath) {
        checkAndAppendPrivateKey(filePath);
    };

    appendKeyMap[CertificateType::server] = appendPrivateKey;
    appendKeyMap[CertificateType::client] = appendPrivateKey;
    appendKeyMap[CertificateType::authority] = [](const std::string&) {};

    // Generate certificate file path
    certFilePath = generateCertFilePath(uploadPath);

    // install the certificate
    install(uploadPath, restore);

    this->emit_object_added();
}

Certificate::Certificate(sdbusplus::bus_t& bus, const std::string& objPath,
                         const CertificateType& type,
                         const std::string& installPath, X509_STORE& x509Store,
                         const std::string& pem, Watch* watchPtr,
                         Manager& parent, bool restore) :
    internal::CertificateInterface(
        bus, objPath.c_str(),
        internal::CertificateInterface::action::defer_emit),
    objectPath(objPath), certType(type), certInstallPath(installPath),
    certWatch(watchPtr), manager(parent)
{
    // Generate certificate file path
    certFilePath = generateUniqueFilePath(installPath);

    // install the certificate
    install(x509Store, pem, restore);

    this->emit_object_added();
}

Certificate::~Certificate()
{
    if (!fs::remove(certFilePath))
    {
        log<level::INFO>("Certificate file not found!",
                         entry("PATH=%s", certFilePath.c_str()));
    }
}

void Certificate::replace(const std::string filePath)
{
    manager.replaceCertificate(this, filePath);
}

void Certificate::install(const std::string& certSrcFilePath, bool restore)
{
    if (restore)
    {
        log<level::DEBUG>("Certificate install ",
                          entry("FILEPATH=%s", certSrcFilePath.c_str()));
    }
    else
    {
        log<level::INFO>("Certificate install ",
                         entry("FILEPATH=%s", certSrcFilePath.c_str()));
    }

    // stop watch for user initiated certificate install
    if (certWatch != nullptr)
    {
        certWatch->stopWatch();
    }

    // Verify the certificate file
    fs::path file(certSrcFilePath);
    if (!fs::exists(file))
    {
        log<level::ERR>("File is Missing",
                        entry("FILE=%s", certSrcFilePath.c_str()));
        elog<InternalFailure>();
    }

    try
    {
        if (fs::file_size(certSrcFilePath) == 0)
        {
            // file is empty
            log<level::ERR>("File is empty",
                            entry("FILE=%s", certSrcFilePath.c_str()));
            elog<InvalidCertificateError>(
                InvalidCertificate::REASON("File is empty"));
        }
    }
    catch (const fs::filesystem_error& e)
    {
        // Log Error message
        log<level::ERR>(e.what(), entry("FILE=%s", certSrcFilePath.c_str()));
        elog<InternalFailure>();
    }

    X509StorePtr x509Store = getX509Store(certSrcFilePath);

    // Load Certificate file into the X509 structure.
    internal::X509Ptr cert = loadCert(certSrcFilePath);

    // Perform validation
    validateCertificateAgainstStore(*x509Store, *cert);
    validateCertificateStartDate(*cert);
    validateCertificateKeyLength(*cert);
    validateCertificateInSSLContext(*cert);

    // Invoke type specific append private key function.
    if (auto it = appendKeyMap.find(certType); it == appendKeyMap.end())
    {
        log<level::ERR>("Unsupported Type",
                        entry("TYPE=%s", certificateTypeToString(certType)));
        elog<InternalFailure>();
    }
    else
    {
        it->second(certSrcFilePath);
    }

    // Invoke type specific compare keys function.
    if (auto it = typeFuncMap.find(certType); it == typeFuncMap.end())
    {
        log<level::ERR>("Unsupported Type",
                        entry("TYPE=%s", certificateTypeToString(certType)));
        elog<InternalFailure>();
    }
    else
    {
        it->second(certSrcFilePath);
    }

    copyCertificate(certSrcFilePath, certFilePath);
    storageUpdate();

    // Keep certificate ID
    certId = generateCertId(*cert);

    // Parse the certificate file and populate properties
    populateProperties(*cert);

    // restart watch
    if (certWatch != nullptr)
    {
        certWatch->startWatch();
    }
}

void Certificate::install(X509_STORE& x509Store, const std::string& pem,
                          bool restore)
{
    if (restore)
    {
        log<level::DEBUG>("Certificate install ",
                          entry("PEM_STR=%s", pem.data()));
    }
    else
    {
        log<level::INFO>("Certificate install ",
                         entry("PEM_STR=%s", pem.data()));
    }

    if (certType != CertificateType::authority)
    {
        log<level::ERR>("Bulk install error: Unsupported Type; only authority "
                        "supports bulk install",
                        entry("TYPE=%s", certificateTypeToString(certType)));
        elog<InternalFailure>();
    }

    // stop watch for user initiated certificate install
    if (certWatch)
    {
        certWatch->stopWatch();
    }

    // Load Certificate file into the X509 structure.
    internal::X509Ptr cert = parseCert(pem);
    // Perform validation; no type specific compare keys function
    validateCertificateAgainstStore(x509Store, *cert);
    validateCertificateStartDate(*cert);
    validateCertificateInSSLContext(*cert);

    // Copy the PEM to the installation path
    dumpCertificate(pem, certFilePath);
    storageUpdate();
    // Keep certificate ID
    certId = generateCertId(*cert);
    // Parse the certificate file and populate properties
    populateProperties(*cert);
    // restart watch
    if (certWatch)
    {
        certWatch->startWatch();
    }
}

void Certificate::populateProperties()
{
    internal::X509Ptr cert = loadCert(certInstallPath);
    populateProperties(*cert);
}

std::string Certificate::getCertId() const
{
    return certId;
}

bool Certificate::isSame(const std::string& certPath)
{
    internal::X509Ptr cert = loadCert(certPath);
    return getCertId() == generateCertId(*cert);
}

void Certificate::storageUpdate()
{
    if (certType == CertificateType::authority)
    {
        // Create symbolic link in the certificate directory
        std::string certFileX509Path;
        try
        {
            if (!certFilePath.empty() &&
                fs::is_regular_file(fs::path(certFilePath)))
            {
                certFileX509Path =
                    generateAuthCertFileX509Path(certFilePath, certInstallPath);
                fs::create_symlink(fs::path(certFilePath),
                                   fs::path(certFileX509Path));
            }
        }
        catch (const std::exception& e)
        {
            log<level::ERR>("Failed to create symlink for certificate",
                            entry("ERR=%s", e.what()),
                            entry("FILE=%s", certFilePath.c_str()),
                            entry("SYMLINK=%s", certFileX509Path.c_str()));
            elog<InternalFailure>();
        }
    }
}

void Certificate::populateProperties(X509& cert)
{
    // Update properties if no error thrown
    BIOMemPtr certBio(BIO_new(BIO_s_mem()), BIO_free);
    PEM_write_bio_X509(certBio.get(), &cert);
    BufMemPtr certBuf(BUF_MEM_new(), BUF_MEM_free);
    BUF_MEM* buf = certBuf.get();
    BIO_get_mem_ptr(certBio.get(), &buf);
    std::string certStr(buf->data, buf->length);
    certificateString(certStr);

    static const int maxKeySize = 4096;
    char subBuffer[maxKeySize] = {0};
    BIOMemPtr subBio(BIO_new(BIO_s_mem()), BIO_free);
    // This pointer cannot be freed independantly.
    X509_NAME* sub = X509_get_subject_name(&cert);
    X509_NAME_print_ex(subBio.get(), sub, 0, XN_FLAG_SEP_COMMA_PLUS);
    BIO_read(subBio.get(), subBuffer, maxKeySize);
    subject(subBuffer);

    char issuerBuffer[maxKeySize] = {0};
    BIOMemPtr issuerBio(BIO_new(BIO_s_mem()), BIO_free);
    // This pointer cannot be freed independantly.
    X509_NAME* issuerName = X509_get_issuer_name(&cert);
    X509_NAME_print_ex(issuerBio.get(), issuerName, 0, XN_FLAG_SEP_COMMA_PLUS);
    BIO_read(issuerBio.get(), issuerBuffer, maxKeySize);
    issuer(issuerBuffer);

    std::vector<std::string> keyUsageList;
    ASN1_BIT_STRING* usage;

    // Go through each usage in the bit string and convert to
    // corresponding string value
    if ((usage = static_cast<ASN1_BIT_STRING*>(
             X509_get_ext_d2i(&cert, NID_key_usage, nullptr, nullptr))))
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
             X509_get_ext_d2i(&cert, NID_ext_key_usage, nullptr, nullptr))))
    {
        for (int i = 0; i < sk_ASN1_OBJECT_num(extUsage); i++)
        {
            keyUsageList.push_back(extendedKeyUsageToRfStr[OBJ_obj2nid(
                sk_ASN1_OBJECT_value(extUsage, i))]);
        }
    }
    keyUsage(keyUsageList);

    int days = 0;
    int secs = 0;

    ASN1TimePtr epoch(ASN1_TIME_new(), ASN1_STRING_free);
    // Set time to 00:00am GMT, Jan 1 1970; format: YYYYMMDDHHMMSSZ
    ASN1_TIME_set_string(epoch.get(), "19700101000000Z");

    static const uint64_t dayToSeconds = 24 * 60 * 60;
    ASN1_TIME* notAfter = X509_get_notAfter(&cert);
    ASN1_TIME_diff(&days, &secs, epoch.get(), notAfter);
    validNotAfter((days * dayToSeconds) + secs);

    ASN1_TIME* notBefore = X509_get_notBefore(&cert);
    ASN1_TIME_diff(&days, &secs, epoch.get(), notBefore);
    validNotBefore((days * dayToSeconds) + secs);
}

void Certificate::checkAndAppendPrivateKey(const std::string& filePath)
{
    BIOMemPtr keyBio(BIO_new(BIO_s_file()), ::BIO_free);
    if (!keyBio)
    {
        log<level::ERR>("Error occurred during BIO_s_file call",
                        entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }
    BIO_read_filename(keyBio.get(), filePath.c_str());

    EVPPkeyPtr priKey(
        PEM_read_bio_PrivateKey(keyBio.get(), nullptr, nullptr, nullptr),
        ::EVP_PKEY_free);
    if (!priKey)
    {
        log<level::INFO>("Private key not present in file",
                         entry("FILE=%s", filePath.c_str()));
        fs::path privateKeyFile = fs::path(certInstallPath).parent_path();
        privateKeyFile = privateKeyFile / defaultPrivateKeyFileName;
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
    internal::X509Ptr cert(X509_new(), ::X509_free);
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
    PEM_read_bio_X509(bioCert.get(), &x509, nullptr, nullptr);

    EVPPkeyPtr pubKey(X509_get_pubkey(cert.get()), ::EVP_PKEY_free);
    if (!pubKey)
    {
        log<level::ERR>("Error occurred during X509_get_pubkey",
                        entry("FILE=%s", filePath.c_str()),
                        entry("ERRCODE=%lu", ERR_get_error()));
        elog<InvalidCertificateError>(
            InvalidCertificate::REASON("Failed to get public key info"));
    }

    BIOMemPtr keyBio(BIO_new(BIO_s_file()), ::BIO_free);
    if (!keyBio)
    {
        log<level::ERR>("Error occurred during BIO_s_file call",
                        entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }
    BIO_read_filename(keyBio.get(), filePath.c_str());

    EVPPkeyPtr priKey(
        PEM_read_bio_PrivateKey(keyBio.get(), nullptr, nullptr, nullptr),
        ::EVP_PKEY_free);
    if (!priKey)
    {
        log<level::ERR>("Error occurred during PEM_read_bio_PrivateKey",
                        entry("FILE=%s", filePath.c_str()),
                        entry("ERRCODE=%lu", ERR_get_error()));
        elog<InvalidCertificateError>(
            InvalidCertificate::REASON("Failed to get private key info"));
    }

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
    int32_t rc = EVP_PKEY_cmp(priKey.get(), pubKey.get());
#else
    int32_t rc = EVP_PKEY_eq(priKey.get(), pubKey.get());
#endif
    if (rc != 1)
    {
        log<level::ERR>("Private key is not matching with Certificate",
                        entry("FILE=%s", filePath.c_str()),
                        entry("ERRCODE=%d", rc));
        return false;
    }
    return true;
}

void Certificate::delete_()
{
    manager.deleteCertificate(this);
}

std::string Certificate::getObjectPath()
{
    return objectPath;
}

std::string Certificate::getCertFilePath()
{
    return certFilePath;
}

void Certificate::setCertFilePath(const std::string& path)
{
    certFilePath = path;
}

void Certificate::setCertInstallPath(const std::string& path)
{
    certInstallPath = path;
}

} // namespace phosphor::certs
