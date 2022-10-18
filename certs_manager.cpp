#include "config.h"

#include "certs_manager.hpp"

#include "x509_utils.hpp"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>
#include <sdeventplus/source/base.hpp>
#include <sdeventplus/source/child.hpp>
#include <utility>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor::certs
{
namespace
{
namespace fs = std::filesystem;
using ::phosphor::logging::commit;
using ::phosphor::logging::elog;
using ::phosphor::logging::entry;
using ::phosphor::logging::level;
using ::phosphor::logging::log;
using ::phosphor::logging::report;

using ::sdbusplus::xyz::openbmc_project::Certs::Error::InvalidCertificate;
using ::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using ::sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
using NotAllowedReason =
    ::phosphor::logging::xyz::openbmc_project::Common::NotAllowed::REASON;
using InvalidCertificateReason = ::phosphor::logging::xyz::openbmc_project::
    Certs::InvalidCertificate::REASON;
using ::sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using Argument =
    ::phosphor::logging::xyz::openbmc_project::Common::InvalidArgument;

// RAII support for openSSL functions.
using X509ReqPtr = std::unique_ptr<X509_REQ, decltype(&::X509_REQ_free)>;
using EVPPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BignumPtr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using X509StorePtr = std::unique_ptr<X509_STORE, decltype(&::X509_STORE_free)>;

constexpr int supportedKeyBitLength = 2048;
constexpr int defaultKeyBitLength = 2048;
// secp224r1 is equal to RSA 2048 KeyBitLength. Refer RFC 5349
constexpr auto defaultKeyCurveID = "secp224r1";
// PEM certificate block markers, defined in go/rfc/7468.
constexpr std::string_view beginCertificate = "-----BEGIN CERTIFICATE-----";
constexpr std::string_view endCertificate = "-----END CERTIFICATE-----";

/**
 * @brief Splits the given authorities list file and returns an array of
 * individual PEM encoded x509 certificate.
 *
 * @param[in] sourceFilePath - Path to the authorities list file.
 *
 * @return An array of individual PEM encoded x509 certificate
 */
std::vector<std::string> splitCertificates(const std::string& sourceFilePath)
{
    std::ifstream inputCertFileStream;
    inputCertFileStream.exceptions(
        std::ifstream::failbit | std::ifstream::badbit | std::ifstream::eofbit);

    std::stringstream pemStream;
    std::vector<std::string> certificatesList;
    try
    {
        inputCertFileStream.open(sourceFilePath);
        pemStream << inputCertFileStream.rdbuf();
        inputCertFileStream.close();
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to read certificates list",
                        entry("ERR=%s", e.what()),
                        entry("SRC=%s", sourceFilePath.c_str()));
        elog<InternalFailure>();
    }
    std::string pem = pemStream.str();
    size_t begin = 0;
    // |begin| points to the current start position for searching the next
    // |beginCertificate| block. When we find the beginning of the certificate,
    // we extract the content between the beginning and the end of the current
    // certificate. And finally we move |begin| to the end of the current
    // certificate to start searching the next potential certificate.
    for (begin = pem.find(beginCertificate, begin); begin != std::string::npos;
         begin = pem.find(beginCertificate, begin))
    {
        size_t end = pem.find(endCertificate, begin);
        if (end == std::string::npos)
        {
            log<level::ERR>(
                "invalid PEM contains a BEGIN identifier without an END");
            elog<InvalidCertificate>(InvalidCertificateReason(
                "invalid PEM contains a BEGIN identifier without an END"));
        }
        end += endCertificate.size();
        certificatesList.emplace_back(pem.substr(begin, end - begin));
        begin = end;
    }
    return certificatesList;
}

} // namespace

Manager::Manager(sdbusplus::bus_t& bus, sdeventplus::Event& event,
                 const char* path, CertificateType type,
                 const std::string& unit, const std::string& installPath) :
    internal::ManagerInterface(bus, path),
    bus(bus), event(event), objectPath(path), certType(type),
    unitToRestart(std::move(unit)), certInstallPath(std::move(installPath)),
    certParentInstallPath(fs::path(certInstallPath).parent_path())
{
    try
    {
        // Create certificate directory if not existing.
        // Set correct certificate directory permissions.
        fs::path certDirectory;
        try
        {
            if (certType == CertificateType::authority)
            {
                certDirectory = certInstallPath;
            }
            else
            {
                certDirectory = certParentInstallPath;
            }

            if (!fs::exists(certDirectory))
            {
                fs::create_directories(certDirectory);
            }

            auto permission = fs::perms::owner_read | fs::perms::owner_write |
                              fs::perms::owner_exec;
            fs::permissions(certDirectory, permission,
                            fs::perm_options::replace);
            storageUpdate();
        }
        catch (const fs::filesystem_error& e)
        {
            log<level::ERR>(
                "Failed to create directory", entry("ERR=%s", e.what()),
                entry("DIRECTORY=%s", certParentInstallPath.c_str()));
            report<InternalFailure>();
        }

        // Generating RSA private key file if certificate type is server/client
        if (certType != CertificateType::authority)
        {
            createRSAPrivateKeyFile();
        }

        // restore any existing certificates
        createCertificates();

        // watch is not required for authority certificates
        if (certType != CertificateType::authority)
        {
            // watch for certificate file create/replace
            certWatchPtr = std::make_unique<
                Watch>(event, certInstallPath, [this]() {
                try
                {
                    // if certificate file existing update it
                    if (!installedCerts.empty())
                    {
                        log<level::INFO>("Inotify callback to update "
                                         "certificate properties");
                        installedCerts[0]->populateProperties();
                    }
                    else
                    {
                        log<level::INFO>(
                            "Inotify callback to create certificate object");
                        createCertificates();
                    }
                }
                catch (const InternalFailure& e)
                {
                    commit<InternalFailure>();
                }
                catch (const InvalidCertificate& e)
                {
                    commit<InvalidCertificate>();
                }
            });
        }
        else
        {
            try
            {
                const std::string singleCertPath = "/etc/ssl/certs/Root-CA.pem";
                if (fs::exists(singleCertPath) && !fs::is_empty(singleCertPath))
                {
                    log<level::NOTICE>(
                        "Legacy certificate detected, will be installed from: ",
                        entry("SINGLE_CERTPATH=%s", singleCertPath.c_str()));
                    install(singleCertPath);
                    if (!fs::remove(singleCertPath))
                    {
                        log<level::ERR>(
                            "Unable to remove old certificate from: ",
                            entry("SINGLE_CERTPATH=%s",
                                  singleCertPath.c_str()));
                        elog<InternalFailure>();
                    }
                }
            }
            catch (const std::exception& ex)
            {
                log<level::ERR>("Error in restoring legacy certificate",
                                entry("ERROR_STR=%s", ex.what()));
            }
        }
    }
    catch (const std::exception& ex)
    {
        log<level::ERR>("Error in certificate manager constructor",
                        entry("ERROR_STR=%s", ex.what()));
    }
}

std::string Manager::install(const std::string filePath)
{
    if (certType != CertificateType::authority && !installedCerts.empty())
    {
        elog<NotAllowed>(NotAllowedReason("Certificate already exist"));
    }
    else if (certType == CertificateType::authority &&
             installedCerts.size() >= maxNumAuthorityCertificates)
    {
        elog<NotAllowed>(NotAllowedReason("Certificates limit reached"));
    }

    std::string certObjectPath;
    if (isCertificateUnique(filePath))
    {
        certObjectPath = objectPath + '/' + std::to_string(certIdCounter);
        installedCerts.emplace_back(std::make_unique<Certificate>(
            bus, certObjectPath, certType, certInstallPath, filePath,
            certWatchPtr.get(), *this, /*restore=*/false));
        reloadOrReset(unitToRestart);
        certIdCounter++;
    }
    else
    {
        elog<NotAllowed>(NotAllowedReason("Certificate already exist"));
    }

    return certObjectPath;
}

std::vector<sdbusplus::message::object_path>
    Manager::installAll(const std::string filePath)
{
    if (certType != CertificateType::authority)
    {
        elog<NotAllowed>(
            NotAllowedReason("The InstallAll interface is only allowed for "
                             "Authority certificates"));
    }

    if (!installedCerts.empty())
    {
        elog<NotAllowed>(NotAllowedReason(
            "There are already root certificates; Call DeleteAll then "
            "InstallAll, or use ReplaceAll"));
    }

    fs::path sourceFile(filePath);
    if (!fs::exists(sourceFile))
    {
        log<level::ERR>("File is Missing", entry("FILE=%s", filePath.c_str()));
        elog<InternalFailure>();
    }
    std::vector<std::string> authorities = splitCertificates(sourceFile);
    if (authorities.size() > maxNumAuthorityCertificates)
    {
        elog<NotAllowed>(NotAllowedReason("Certificates limit reached"));
    }

    log<level::INFO>("Starts authority list install");

    fs::path authorityStore(certInstallPath);
    fs::path authoritiesListFile =
        authorityStore / defaultAuthoritiesListFileName;

    // Atomically install all the certificates
    fs::path tempPath = Certificate::generateUniqueFilePath(authorityStore);
    fs::create_directory(tempPath);
    // Copies the authorities list
    Certificate::copyCertificate(sourceFile,
                                 tempPath / defaultAuthoritiesListFileName);
    std::vector<std::unique_ptr<Certificate>> tempCertificates;
    uint64_t tempCertIdCounter = certIdCounter;
    X509StorePtr x509Store = getX509Store(sourceFile);
    for (const auto& authority : authorities)
    {
        std::string certObjectPath =
            objectPath + '/' + std::to_string(tempCertIdCounter);
        tempCertificates.emplace_back(std::make_unique<Certificate>(
            bus, certObjectPath, certType, tempPath, *x509Store, authority,
            certWatchPtr.get(), *this, /*restore=*/false));
        tempCertIdCounter++;
    }

    // We are good now, issue swap
    installedCerts = std::move(tempCertificates);
    certIdCounter = tempCertIdCounter;
    // Rename all the certificates including the authorities list
    for (const fs::path& f : fs::directory_iterator(tempPath))
    {
        if (fs::is_symlink(f))
        {
            continue;
        }
        fs::rename(/*from=*/f, /*to=*/certInstallPath / f.filename());
    }
    // Update file locations and create symbol links
    for (const auto& cert : installedCerts)
    {
        cert->setCertInstallPath(certInstallPath);
        cert->setCertFilePath(certInstallPath /
                              fs::path(cert->getCertFilePath()).filename());
        cert->storageUpdate();
    }
    // Remove the temporary folder
    fs::remove_all(tempPath);

    std::vector<sdbusplus::message::object_path> objects;
    for (const auto& certificate : installedCerts)
    {
        objects.emplace_back(certificate->getObjectPath());
    }

    log<level::INFO>("Finishes authority list install; reload units starts");
    reloadOrReset(unitToRestart);
    return objects;
}

std::vector<sdbusplus::message::object_path>
    Manager::replaceAll(std::string filePath)
{
    installedCerts.clear();
    certIdCounter = 1;
    storageUpdate();
    return installAll(std::move(filePath));
}

void Manager::deleteAll()
{
    // TODO: #Issue 4 when a certificate is deleted system auto generates
    // certificate file. At present we are not supporting creation of
    // certificate object for the auto-generated certificate file as
    // deletion if only applicable for REST server and Bmcweb does not allow
    // deletion of certificates
    installedCerts.clear();
    // If the authorities list exists, delete it as well
    if (certType == CertificateType::authority)
    {
        if (fs::path authoritiesList =
                fs::path(certInstallPath) / defaultAuthoritiesListFileName;
            fs::exists(authoritiesList))
        {
            fs::remove(authoritiesList);
        }
    }
    certIdCounter = 1;
    storageUpdate();
    reloadOrReset(unitToRestart);
}

void Manager::deleteCertificate(const Certificate* const certificate)
{
    std::vector<std::unique_ptr<Certificate>>::iterator const& certIt =
        std::find_if(installedCerts.begin(), installedCerts.end(),
                     [certificate](std::unique_ptr<Certificate> const& cert) {
                         return (cert.get() == certificate);
                     });
    if (certIt != installedCerts.end())
    {
        installedCerts.erase(certIt);
        storageUpdate();
        reloadOrReset(unitToRestart);
    }
    else
    {
        log<level::ERR>("Certificate does not exist",
                        entry("ID=%s", certificate->getCertId().c_str()));
        elog<InternalFailure>();
    }
}

void Manager::replaceCertificate(Certificate* const certificate,
                                 const std::string& filePath)
{
    if (isCertificateUnique(filePath, certificate))
    {
        certificate->install(filePath, false);
        storageUpdate();
        reloadOrReset(unitToRestart);
    }
    else
    {
        elog<NotAllowed>(NotAllowedReason("Certificate already exist"));
    }
}

std::string Manager::generateCSR(
    std::vector<std::string> alternativeNames, std::string challengePassword,
    std::string city, std::string commonName, std::string contactPerson,
    std::string country, std::string email, std::string givenName,
    std::string initials, int64_t keyBitLength, std::string keyCurveId,
    std::string keyPairAlgorithm, std::vector<std::string> keyUsage,
    std::string organization, std::string organizationalUnit, std::string state,
    std::string surname, std::string unstructuredName)
{
    // We support only one CSR.
    csrPtr.reset(nullptr);
    auto pid = fork();
    if (pid == -1)
    {
        log<level::ERR>("Error occurred during forking process");
        report<InternalFailure>();
    }
    else if (pid == 0)
    {
        try
        {
            generateCSRHelper(alternativeNames, challengePassword, city,
                              commonName, contactPerson, country, email,
                              givenName, initials, keyBitLength, keyCurveId,
                              keyPairAlgorithm, keyUsage, organization,
                              organizationalUnit, state, surname,
                              unstructuredName);
            exit(EXIT_SUCCESS);
        }
        catch (const InternalFailure& e)
        {
            // commit the error reported in child process and exit
            // Callback method from SDEvent Loop looks for exit status
            exit(EXIT_FAILURE);
            commit<InternalFailure>();
        }
        catch (const InvalidArgument& e)
        {
            // commit the error reported in child process and exit
            // Callback method from SDEvent Loop looks for exit status
            exit(EXIT_FAILURE);
            commit<InvalidArgument>();
        }
    }
    else
    {
        using namespace sdeventplus::source;
        Child::Callback callback = [this](Child& eventSource,
                                          const siginfo_t* si) {
            eventSource.set_enabled(Enabled::On);
            if (si->si_status != 0)
            {
                this->createCSRObject(Status::failure);
            }
            else
            {
                this->createCSRObject(Status::success);
            }
        };
        try
        {
            sigset_t ss;
            if (sigemptyset(&ss) < 0)
            {
                log<level::ERR>("Unable to initialize signal set");
                elog<InternalFailure>();
            }
            if (sigaddset(&ss, SIGCHLD) < 0)
            {
                log<level::ERR>("Unable to add signal to signal set");
                elog<InternalFailure>();
            }

            // Block SIGCHLD first, so that the event loop can handle it
            if (sigprocmask(SIG_BLOCK, &ss, nullptr) < 0)
            {
                log<level::ERR>("Unable to block signal");
                elog<InternalFailure>();
            }
            if (childPtr)
            {
                childPtr.reset();
            }
            childPtr = std::make_unique<Child>(event, pid, WEXITED | WSTOPPED,
                                               std::move(callback));
        }
        catch (const InternalFailure& e)
        {
            commit<InternalFailure>();
        }
    }
    auto csrObjectPath = objectPath + '/' + "csr";
    return csrObjectPath;
}

std::vector<std::unique_ptr<Certificate>>& Manager::getCertificates()
{
    return installedCerts;
}

void Manager::generateCSRHelper(
    std::vector<std::string> alternativeNames, std::string challengePassword,
    std::string city, std::string commonName, std::string contactPerson,
    std::string country, std::string email, std::string givenName,
    std::string initials, int64_t keyBitLength, std::string keyCurveId,
    std::string keyPairAlgorithm, std::vector<std::string> keyUsage,
    std::string organization, std::string organizationalUnit, std::string state,
    std::string surname, std::string unstructuredName)
{
    int ret = 0;

    // set version of x509 req
    int nVersion = 1;
    // TODO: Issue#6 need to make version number configurable
    X509ReqPtr x509Req(X509_REQ_new(), ::X509_REQ_free);
    ret = X509_REQ_set_version(x509Req.get(), nVersion);
    if (ret == 0)
    {
        log<level::ERR>("Error occurred during X509_REQ_set_version call");
        elog<InternalFailure>();
    }

    // set subject of x509 req
    X509_NAME* x509Name = X509_REQ_get_subject_name(x509Req.get());

    if (!alternativeNames.empty())
    {
        for (auto& name : alternativeNames)
        {
            addEntry(x509Name, "subjectAltName", name);
        }
    }
    addEntry(x509Name, "challengePassword", challengePassword);
    addEntry(x509Name, "L", city);
    addEntry(x509Name, "CN", commonName);
    addEntry(x509Name, "name", contactPerson);
    addEntry(x509Name, "C", country);
    addEntry(x509Name, "emailAddress", email);
    addEntry(x509Name, "GN", givenName);
    addEntry(x509Name, "initials", initials);
    addEntry(x509Name, "algorithm", keyPairAlgorithm);
    if (!keyUsage.empty())
    {
        for (auto& usage : keyUsage)
        {
            if (isExtendedKeyUsage(usage))
            {
                addEntry(x509Name, "extendedKeyUsage", usage);
            }
            else
            {
                addEntry(x509Name, "keyUsage", usage);
            }
        }
    }
    addEntry(x509Name, "O", organization);
    addEntry(x509Name, "OU", organizationalUnit);
    addEntry(x509Name, "ST", state);
    addEntry(x509Name, "SN", surname);
    addEntry(x509Name, "unstructuredName", unstructuredName);

    EVPPkeyPtr pKey(nullptr, ::EVP_PKEY_free);

    log<level::INFO>("Given Key pair algorithm",
                     entry("KEYPAIRALGORITHM=%s", keyPairAlgorithm.c_str()));

    // Used EC algorithm as default if user did not give algorithm type.
    if (keyPairAlgorithm == "RSA")
        pKey = getRSAKeyPair(keyBitLength);
    else if ((keyPairAlgorithm == "EC") || (keyPairAlgorithm.empty()))
        pKey = generateECKeyPair(keyCurveId);
    else
    {
        log<level::ERR>("Given Key pair algorithm is not supported. Supporting "
                        "RSA and EC only");
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("KEYPAIRALGORITHM"),
            Argument::ARGUMENT_VALUE(keyPairAlgorithm.c_str()));
    }

    ret = X509_REQ_set_pubkey(x509Req.get(), pKey.get());
    if (ret == 0)
    {
        log<level::ERR>("Error occurred while setting Public key");
        elog<InternalFailure>();
    }

    // Write private key to file
    writePrivateKey(pKey, defaultPrivateKeyFileName);

    // set sign key of x509 req
    ret = X509_REQ_sign(x509Req.get(), pKey.get(), EVP_sha256());
    if (ret == 0)
    {
        log<level::ERR>("Error occurred while signing key of x509");
        elog<InternalFailure>();
    }

    log<level::INFO>("Writing CSR to file");
    fs::path csrFilePath = certParentInstallPath / defaultCSRFileName;
    writeCSR(csrFilePath.string(), x509Req);
}

bool Manager::isExtendedKeyUsage(const std::string& usage)
{
    const static std::array<const char*, 6> usageList = {
        "ServerAuthentication", "ClientAuthentication", "OCSPSigning",
        "Timestamping",         "CodeSigning",          "EmailProtection"};
    auto it = std::find_if(
        usageList.begin(), usageList.end(),
        [&usage](const char* s) { return (strcmp(s, usage.c_str()) == 0); });
    return it != usageList.end();
}
EVPPkeyPtr Manager::generateRSAKeyPair(const int64_t keyBitLength)
{
    int64_t keyBitLen = keyBitLength;
    // set keybit length to default value if not set
    if (keyBitLen <= 0)
    {
        log<level::INFO>(
            "KeyBitLength is not given.Hence, using default KeyBitLength",
            entry("DEFAULTKEYBITLENGTH=%d", defaultKeyBitLength));
        keyBitLen = defaultKeyBitLength;
    }

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)

    // generate rsa key
    BignumPtr bne(BN_new(), ::BN_free);
    auto ret = BN_set_word(bne.get(), RSA_F4);
    if (ret == 0)
    {
        log<level::ERR>("Error occurred during BN_set_word call");
        elog<InternalFailure>();
    }
    using RSAPtr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
    RSAPtr rsa(RSA_new(), ::RSA_free);
    ret = RSA_generate_key_ex(rsa.get(), keyBitLen, bne.get(), nullptr);
    if (ret != 1)
    {
        log<level::ERR>("Error occurred during RSA_generate_key_ex call",
                        entry("KEYBITLENGTH=%PRIu64", keyBitLen));
        elog<InternalFailure>();
    }

    // set public key of x509 req
    EVPPkeyPtr pKey(EVP_PKEY_new(), ::EVP_PKEY_free);
    ret = EVP_PKEY_assign_RSA(pKey.get(), rsa.get());
    if (ret == 0)
    {
        log<level::ERR>("Error occurred during assign rsa key into EVP");
        elog<InternalFailure>();
    }
    // Now |rsa| is managed by |pKey|
    rsa.release();
    return pKey;

#else
    auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&::EVP_PKEY_CTX_free)>(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), &::EVP_PKEY_CTX_free);
    if (!ctx)
    {
        log<level::ERR>("Error occurred creating EVP_PKEY_CTX from algorithm");
        elog<InternalFailure>();
    }

    if ((EVP_PKEY_keygen_init(ctx.get()) <= 0) ||
        (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), keyBitLen) <= 0))

    {
        log<level::ERR>("Error occurred initializing keygen context");
        elog<InternalFailure>();
    }

    EVP_PKEY* pKey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pKey) <= 0)
    {
        log<level::ERR>("Error occurred during generate EC key");
        elog<InternalFailure>();
    }

    return {pKey, &::EVP_PKEY_free};
#endif
}

EVPPkeyPtr Manager::generateECKeyPair(const std::string& curveId)
{
    std::string curId(curveId);

    if (curId.empty())
    {
        log<level::INFO>(
            "KeyCurveId is not given. Hence using default curve id",
            entry("DEFAULTKEYCURVEID=%s", defaultKeyCurveID));
        curId = defaultKeyCurveID;
    }

    int ecGrp = OBJ_txt2nid(curId.c_str());
    if (ecGrp == NID_undef)
    {
        log<level::ERR>(
            "Error occurred during convert the curve id string format into NID",
            entry("KEYCURVEID=%s", curId.c_str()));
        elog<InternalFailure>();
    }

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)

    EC_KEY* ecKey = EC_KEY_new_by_curve_name(ecGrp);

    if (ecKey == nullptr)
    {
        log<level::ERR>(
            "Error occurred during create the EC_Key object from NID",
            entry("ECGROUP=%d", ecGrp));
        elog<InternalFailure>();
    }

    // If you want to save a key and later load it with
    // SSL_CTX_use_PrivateKey_file, then you must set the OPENSSL_EC_NAMED_CURVE
    // flag on the key.
    EC_KEY_set_asn1_flag(ecKey, OPENSSL_EC_NAMED_CURVE);

    int ret = EC_KEY_generate_key(ecKey);

    if (ret == 0)
    {
        EC_KEY_free(ecKey);
        log<level::ERR>("Error occurred during generate EC key");
        elog<InternalFailure>();
    }

    EVPPkeyPtr pKey(EVP_PKEY_new(), ::EVP_PKEY_free);
    ret = EVP_PKEY_assign_EC_KEY(pKey.get(), ecKey);
    if (ret == 0)
    {
        EC_KEY_free(ecKey);
        log<level::ERR>("Error occurred during assign EC Key into EVP");
        elog<InternalFailure>();
    }

    return pKey;

#else
    auto holderOfKey = [](EVP_PKEY* key) {
        return std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>{
            key, &::EVP_PKEY_free};
    };

    // Create context to set up curve parameters.
    auto ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&::EVP_PKEY_CTX_free)>(
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), &::EVP_PKEY_CTX_free);
    if (!ctx)
    {
        log<level::ERR>("Error occurred creating EVP_PKEY_CTX for params");
        elog<InternalFailure>();
    }

    // Set up curve parameters.
    EVP_PKEY* params = nullptr;

    if ((EVP_PKEY_paramgen_init(ctx.get()) <= 0) ||
        (EVP_PKEY_CTX_set_ec_param_enc(ctx.get(), OPENSSL_EC_NAMED_CURVE) <=
         0) ||
        (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), ecGrp) <= 0) ||
        (EVP_PKEY_paramgen(ctx.get(), &params) <= 0))
    {
        log<level::ERR>("Error occurred setting curve parameters");
        elog<InternalFailure>();
    }

    // Move parameters to RAII holder.
    auto pparms = holderOfKey(params);

    // Create new context for key.
    ctx.reset(EVP_PKEY_CTX_new_from_pkey(nullptr, params, nullptr));

    if (!ctx || (EVP_PKEY_keygen_init(ctx.get()) <= 0))
    {
        log<level::ERR>("Error occurred initializing keygen context");
        elog<InternalFailure>();
    }

    EVP_PKEY* pKey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pKey) <= 0)
    {
        log<level::ERR>("Error occurred during generate EC key");
        elog<InternalFailure>();
    }

    return holderOfKey(pKey);
#endif
}

void Manager::writePrivateKey(const EVPPkeyPtr& pKey,
                              const std::string& privKeyFileName)
{
    log<level::INFO>("Writing private key to file");
    // write private key to file
    fs::path privKeyPath = certParentInstallPath / privKeyFileName;

    FILE* fp = std::fopen(privKeyPath.c_str(), "w");
    if (fp == nullptr)
    {
        log<level::ERR>("Error occurred creating private key file");
        elog<InternalFailure>();
    }
    int ret =
        PEM_write_PrivateKey(fp, pKey.get(), nullptr, nullptr, 0, 0, nullptr);
    std::fclose(fp);
    if (ret == 0)
    {
        log<level::ERR>("Error occurred while writing private key to file");
        elog<InternalFailure>();
    }
}

void Manager::addEntry(X509_NAME* x509Name, const char* field,
                       const std::string& bytes)
{
    if (bytes.empty())
    {
        return;
    }
    int ret = X509_NAME_add_entry_by_txt(
        x509Name, field, MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(bytes.c_str()), -1, -1, 0);
    if (ret != 1)
    {
        log<level::ERR>("Unable to set entry", entry("FIELD=%s", field),
                        entry("VALUE=%s", bytes.c_str()));
        elog<InternalFailure>();
    }
}

void Manager::createCSRObject(const Status& status)
{
    if (csrPtr)
    {
        csrPtr.reset(nullptr);
    }
    auto csrObjectPath = objectPath + '/' + "csr";
    csrPtr = std::make_unique<CSR>(bus, csrObjectPath.c_str(),
                                   certInstallPath.c_str(), status);
}

void Manager::writeCSR(const std::string& filePath, const X509ReqPtr& x509Req)
{
    if (fs::exists(filePath))
    {
        log<level::INFO>("Removing the existing file",
                         entry("FILENAME=%s", filePath.c_str()));
        if (!fs::remove(filePath.c_str()))
        {
            log<level::ERR>("Unable to remove the file",
                            entry("FILENAME=%s", filePath.c_str()));
            elog<InternalFailure>();
        }
    }

    FILE* fp = nullptr;

    if ((fp = std::fopen(filePath.c_str(), "w")) == nullptr)
    {
        log<level::ERR>("Error opening the file to write the CSR",
                        entry("FILENAME=%s", filePath.c_str()));
        elog<InternalFailure>();
    }

    int rc = PEM_write_X509_REQ(fp, x509Req.get());
    if (!rc)
    {
        log<level::ERR>("PEM write routine failed",
                        entry("FILENAME=%s", filePath.c_str()));
        std::fclose(fp);
        elog<InternalFailure>();
    }
    std::fclose(fp);
}

void Manager::createCertificates()
{
    auto certObjectPath = objectPath + '/';

    if (certType == CertificateType::authority)
    {
        // Check whether install path is a directory.
        if (!fs::is_directory(certInstallPath))
        {
            log<level::ERR>("Certificate installation path exists and it is "
                            "not a directory");
            elog<InternalFailure>();
        }

        // If the authorities list exists, recover from it and return
        if (fs::path authoritiesListFilePath =
                fs::path(certInstallPath) / defaultAuthoritiesListFileName;
            fs::exists(authoritiesListFilePath))
        {
            // remove all other files and directories
            for (auto& path : fs::directory_iterator(certInstallPath))
            {
                if (path.path() != authoritiesListFilePath)
                {
                    fs::remove_all(path);
                }
            }
            installAll(authoritiesListFilePath);
            return;
        }

        for (auto& path : fs::directory_iterator(certInstallPath))
        {
            try
            {
                // Assume here any regular file located in certificate directory
                // contains certificates body. Do not want to use soft links
                // would add value.
                if (fs::is_regular_file(path))
                {
                    installedCerts.emplace_back(std::make_unique<Certificate>(
                        bus, certObjectPath + std::to_string(certIdCounter++),
                        certType, certInstallPath, path.path(),
                        certWatchPtr.get(), *this, /*restore=*/true));
                }
            }
            catch (const InternalFailure& e)
            {
                report<InternalFailure>();
            }
            catch (const InvalidCertificate& e)
            {
                report<InvalidCertificate>(InvalidCertificateReason(
                    "Existing certificate file is corrupted"));
            }
        }
    }
    else if (fs::exists(certInstallPath))
    {
        try
        {
            installedCerts.emplace_back(std::make_unique<Certificate>(
                bus, certObjectPath + '1', certType, certInstallPath,
                certInstallPath, certWatchPtr.get(), *this, /*restore=*/false));
        }
        catch (const InternalFailure& e)
        {
            report<InternalFailure>();
        }
        catch (const InvalidCertificate& e)
        {
            report<InvalidCertificate>(InvalidCertificateReason(
                "Existing certificate file is corrupted"));
        }
    }
}

void Manager::createRSAPrivateKeyFile()
{
    fs::path rsaPrivateKeyFileName =
        certParentInstallPath / defaultRSAPrivateKeyFileName;

    try
    {
        if (!fs::exists(rsaPrivateKeyFileName))
        {
            writePrivateKey(generateRSAKeyPair(supportedKeyBitLength),
                            defaultRSAPrivateKeyFileName);
        }
    }
    catch (const InternalFailure& e)
    {
        report<InternalFailure>();
    }
}

EVPPkeyPtr Manager::getRSAKeyPair(const int64_t keyBitLength)
{
    if (keyBitLength != supportedKeyBitLength)
    {
        log<level::ERR>(
            "Given Key bit length is not supported",
            entry("GIVENKEYBITLENGTH=%d", keyBitLength),
            entry("SUPPORTEDKEYBITLENGTH=%d", supportedKeyBitLength));
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("KEYBITLENGTH"),
            Argument::ARGUMENT_VALUE(std::to_string(keyBitLength).c_str()));
    }
    fs::path rsaPrivateKeyFileName =
        certParentInstallPath / defaultRSAPrivateKeyFileName;

    FILE* privateKeyFile = std::fopen(rsaPrivateKeyFileName.c_str(), "r");
    if (!privateKeyFile)
    {
        log<level::ERR>("Unable to open RSA private key file to read",
                        entry("RSAKEYFILE=%s", rsaPrivateKeyFileName.c_str()),
                        entry("ERRORREASON=%s", strerror(errno)));
        elog<InternalFailure>();
    }

    EVPPkeyPtr privateKey(
        PEM_read_PrivateKey(privateKeyFile, nullptr, nullptr, nullptr),
        ::EVP_PKEY_free);
    std::fclose(privateKeyFile);

    if (!privateKey)
    {
        log<level::ERR>("Error occurred during PEM_read_PrivateKey call");
        elog<InternalFailure>();
    }
    return privateKey;
}

void Manager::storageUpdate()
{
    if (certType == CertificateType::authority)
    {
        // Remove symbolic links in the certificate directory
        for (auto& certPath : fs::directory_iterator(certInstallPath))
        {
            try
            {
                if (fs::is_symlink(certPath))
                {
                    fs::remove(certPath);
                }
            }
            catch (const std::exception& e)
            {
                log<level::ERR>(
                    "Failed to remove symlink for certificate",
                    entry("ERR=%s", e.what()),
                    entry("SYMLINK=%s", certPath.path().string().c_str()));
                elog<InternalFailure>();
            }
        }
    }

    for (const auto& cert : installedCerts)
    {
        cert->storageUpdate();
    }
}

void Manager::reloadOrReset(const std::string& unit)
{
    if (!unit.empty())
    {
        try
        {
            constexpr auto defaultSystemdService = "org.freedesktop.systemd1";
            constexpr auto defaultSystemdObjectPath =
                "/org/freedesktop/systemd1";
            constexpr auto defaultSystemdInterface =
                "org.freedesktop.systemd1.Manager";
            auto method = bus.new_method_call(
                defaultSystemdService, defaultSystemdObjectPath,
                defaultSystemdInterface, "ReloadOrRestartUnit");
            method.append(unit, "replace");
            bus.call_noreply(method);
        }
        catch (const sdbusplus::exception_t& e)
        {
            log<level::ERR>("Failed to reload or restart service",
                            entry("ERR=%s", e.what()),
                            entry("UNIT=%s", unit.c_str()));
            elog<InternalFailure>();
        }
    }
}

bool Manager::isCertificateUnique(const std::string& filePath,
                                  const Certificate* const certToDrop)
{
    if (std::any_of(
            installedCerts.begin(), installedCerts.end(),
            [&filePath, certToDrop](std::unique_ptr<Certificate> const& cert) {
                return cert.get() != certToDrop && cert->isSame(filePath);
            }))
    {
        return false;
    }
    else
    {
        return true;
    }
}

} // namespace phosphor::certs
