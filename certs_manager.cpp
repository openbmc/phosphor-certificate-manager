#include "config.h"

#include "certs_manager.hpp"

#include "x509_utils.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <sys/socket.h>
#include <unistd.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>
#include <sdeventplus/source/base.hpp>
#include <sdeventplus/source/child.hpp>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

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
#include <regex>
#include <utility>
namespace phosphor::certs
{
namespace
{
namespace fs = std::filesystem;
using ::phosphor::logging::commit;
using ::phosphor::logging::elog;
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

struct StackX509ExtensionDeleter
{
    void operator()(STACK_OF(X509_EXTENSION) * ptr)
    {
        sk_X509_EXTENSION_pop_free(ptr, X509_EXTENSION_free);
    }
};
using X509ExtListPtr =
    std::unique_ptr<STACK_OF(X509_EXTENSION),
                    phosphor::certs::StackX509ExtensionDeleter>;

struct GeneralNameDeleter
{
    void operator()(GENERAL_NAME* ptr) const
    {
        GENERAL_NAME_free(ptr);
    }
};

using GeneralNamePtr =
    std::unique_ptr<GENERAL_NAME, phosphor::certs::GeneralNameDeleter>;

struct GeneralNamesDeleter
{
    void operator()(STACK_OF(GENERAL_NAME) * ptr) const
    {
        sk_GENERAL_NAME_pop_free(ptr, GENERAL_NAME_free);
    }
};

using GeneralNamesPtr = std::unique_ptr<STACK_OF(GENERAL_NAME),
                                        phosphor::certs::GeneralNamesDeleter>;

struct X509ExtensionDeleter
{
    void operator()(X509_EXTENSION *ptr) const
    {
        if (ptr)
        {
            X509_EXTENSION_free(ptr);
        }
    }
};

using X509ExtensionPtr = std::unique_ptr<X509_EXTENSION, X509ExtensionDeleter>;

constexpr int IPV4_LENGTH = 4;
constexpr int IPV6_LENGTH = 16;
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
        lg2::error("Failed to read certificates list, ERR:{ERR}, SRC:{SRC}",
                   "ERR", e, "SRC", sourceFilePath);
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
            lg2::error(
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
    internal::ManagerInterface(bus, path), bus(bus), event(event),
    objectPath(path), certType(type), unitToRestart(std::move(unit)),
    certInstallPath(std::move(installPath)),
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
            lg2::error(
                "Failed to create directory, ERR:{ERR}, DIRECTORY:{DIRECTORY}",
                "ERR", e, "DIRECTORY", certParentInstallPath);
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
                        lg2::info("Inotify callback to update "
                                  "certificate properties");
                        installedCerts[0]->populateProperties();
                    }
                    else
                    {
                        lg2::info(
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
                    lg2::notice(
                        "Legacy certificate detected, will be installed from,"
                        "SINGLE_CERTPATH:{SINGLE_CERTPATH}",
                        "SINGLE_CERTPATH", singleCertPath);
                    install(singleCertPath);
                    if (!fs::remove(singleCertPath))
                    {
                        lg2::error("Unable to remove old certificate from,"
                                   "SINGLE_CERTPATH:{SINGLE_CERTPATH}",
                                   "SINGLE_CERTPATH", singleCertPath);
                        elog<InternalFailure>();
                    }
                }
            }
            catch (const std::exception& ex)
            {
                lg2::error(
                    "Error in restoring legacy certificate, ERROR_STR:{ERROR_STR}",
                    "ERROR_STR", ex);
            }
        }
    }
    catch (const std::exception& ex)
    {
        lg2::error(
            "Error in certificate manager constructor, ERROR_STR:{ERROR_STR}",
            "ERROR_STR", ex);
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
        elog<NotAllowed>(NotAllowedReason(
            "The InstallAll interface is only allowed for "
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
        lg2::error("File is Missing, FILE:{FILE}", "FILE", filePath);
        elog<InternalFailure>();
    }
    std::vector<std::string> authorities = splitCertificates(sourceFile);
    if (authorities.size() > maxNumAuthorityCertificates)
    {
        elog<NotAllowed>(NotAllowedReason("Certificates limit reached"));
    }

    lg2::info("Starts authority list install");

    fs::path authorityStore(certInstallPath);

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
        cert->setCertFilePath(
            certInstallPath / fs::path(cert->getCertFilePath()).filename());
        cert->storageUpdate();
    }
    // Remove the temporary folder
    fs::remove_all(tempPath);

    std::vector<sdbusplus::message::object_path> objects;
    for (const auto& certificate : installedCerts)
    {
        objects.emplace_back(certificate->getObjectPath());
    }

    lg2::info("Finishes authority list install; reload units starts");
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
    const std::vector<std::unique_ptr<Certificate>>::iterator& certIt =
        std::find_if(installedCerts.begin(), installedCerts.end(),
                     [certificate](const std::unique_ptr<Certificate>& cert) {
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
        lg2::error("Certificate does not exist, ID:{ID}", "ID",
                   certificate->getCertId());
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
        lg2::error("Error occurred during forking process");
        report<InternalFailure>();
    }
    else if (pid == 0)
    {
        try
        {
            generateCSRHelper(
                alternativeNames, challengePassword, city, commonName,
                contactPerson, country, email, givenName, initials,
                keyBitLength, keyCurveId, keyPairAlgorithm, keyUsage,
                organization, organizationalUnit, state, surname,
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
        Child::Callback callback =
            [this](Child& eventSource, const siginfo_t* si) {
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
                lg2::error("Unable to initialize signal set");
                elog<InternalFailure>();
            }
            if (sigaddset(&ss, SIGCHLD) < 0)
            {
                lg2::error("Unable to add signal to signal set");
                elog<InternalFailure>();
            }

            // Block SIGCHLD first, so that the event loop can handle it
            if (sigprocmask(SIG_BLOCK, &ss, nullptr) < 0)
            {
                lg2::error("Unable to block signal");
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

int getSANType(const std::string &name)
{
   if (name.find('@') != std::string::npos)
   {
        if (!std::regex_match(
                name,
                std::regex(
                    R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)")))
        {
            lg2::error("Invalid Email input for subAltName");
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("CSR"),
                                  Argument::ARGUMENT_VALUE(name.c_str()));
        }
        return GEN_EMAIL;
    }
    else if (name.find("://") != std::string::npos)
    {
        std::regex uriRegex(R"(^https?://[a-zA-Z0-9.\-_/]+$)",
                            std::regex_constants::icase);
        if (std::regex_match(name, uriRegex))
        {
            return GEN_URI;
        }
        else
        {
            lg2::error("Invalid URI input for subAltName");
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("CSR"),
                                  Argument::ARGUMENT_VALUE(name.c_str()));
            return -1;
        }
    }
    else if (name.find(':') != std::string::npos)
    {
        struct sockaddr_in6 sa6;
        if (inet_pton(AF_INET6, name.c_str(), &(sa6.sin6_addr)) == 1)
        {
            return GEN_IPADD;
        }
        else 
        {
            lg2::error("Invalid IPv6 address input for subAltName");
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("CSR"),
                                  Argument::ARGUMENT_VALUE(name.c_str()));
            return -1;
        }
    }
    else if (name.find('.') != std::string::npos ||
            std::regex_match(name, std::regex(R"(^[a-zA-Z0-9\-]+$)")))
    {
        if (std::regex_match(name, std::regex(R"([0-9.]+)")))
        {
            struct sockaddr_in sa4;
            if (inet_pton(AF_INET, name.c_str(), &(sa4.sin_addr)) == 1)
            {
                return GEN_IPADD;
            }
            else
            {
                lg2::error("Invalid IPv4 address input for SubAltName.");
                elog<InvalidArgument>(Argument::ARGUMENT_NAME("CSR"),
                                      Argument::ARGUMENT_VALUE(name.c_str()));
                return -1;
            }
        }
        if (std::regex_match(
                name,
                std::regex(
                    R"(^(([a-zA-Z]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*)|localhost|[a-zA-Z0-9\-]+)$)")))
        {
            return GEN_DNS;
        }
        lg2::error(
            "Invalid input: neither a valid IPv4 address nor a valid DNS name.");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("CSR"),
                              Argument::ARGUMENT_VALUE(name.c_str()));
        return -1;
    }
    else if (name.starts_with("OID."))
    {
        return GEN_RID;
    }
    else
    {
        lg2::error("Unsupported option for SAN ");
        return -1;
    }
}

bool processAlternativeName(const std::string &altName, GeneralNamesPtr &gens) 
{

    GeneralNamePtr gen(GENERAL_NAME_new());
    int type = getSANType(altName);
    gen->type = type;
    if (type == GEN_DNS || type == GEN_URI)
    {
        gen->d.ia5 = ASN1_IA5STRING_new();
        ASN1_STRING_set(gen->d.ia5, altName.c_str(), altName.length());
    }
    else if (type == GEN_EMAIL)
    {
        gen->d.rfc822Name = ASN1_IA5STRING_new();
        ASN1_STRING_set(gen->d.rfc822Name, altName.c_str(), altName.length());
    }
    else if (type == GEN_IPADD)
    {
        gen->d.ip = ASN1_OCTET_STRING_new();
        std::array<unsigned char, 16> ipBuffer = {};
        int ipLength = 0;
        if (inet_pton(AF_INET, altName.c_str(), ipBuffer.data()) == 1)
        {
            ipLength = IPV4_LENGTH;
        }
        else if (inet_pton(AF_INET6, altName.c_str(), ipBuffer.data()) == 1)
        {
            ipLength = IPV6_LENGTH;
        }
        else 
        {
            return false;
        }
        ASN1_OCTET_STRING_set(gen->d.ip, ipBuffer.data(), ipLength);
    }
    else
    {
        return false;
    }

    if (sk_GENERAL_NAME_push(gens.get(), gen.get()))
    {
        gen.release();
        return true;
    }

    return false;
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
    X509ReqPtr x509Req(X509_REQ_new(), ::X509_REQ_free);

    // set subject of x509 req
    X509_NAME* x509Name = X509_REQ_get_subject_name(x509Req.get());
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

    lg2::info("Given Key pair algorithm, KEYPAIRALGORITHM:{KEYPAIRALGORITHM}",
              "KEYPAIRALGORITHM", keyPairAlgorithm);

    // Used EC algorithm as default if user did not give algorithm type.
    if (keyPairAlgorithm == "RSA")
        pKey = getRSAKeyPair(keyBitLength);
    else if ((keyPairAlgorithm == "EC") || (keyPairAlgorithm.empty()))
        pKey = generateECKeyPair(keyCurveId);
    else
    {
        lg2::error("Given Key pair algorithm is not supported. Supporting "
                   "RSA and EC only");
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("KEYPAIRALGORITHM"),
            Argument::ARGUMENT_VALUE(keyPairAlgorithm.c_str()));
    }

    // set subjectAltName extension
    if (!alternativeNames.empty())
    {
        GeneralNamesPtr gens(sk_GENERAL_NAME_new_null());
        for (const auto& altName : alternativeNames)
        {
            if (!processAlternativeName(altName, gens))
            {
                lg2::error("Error creating subjectAltName extension");
                elog<InternalFailure>();
            }
        }        
        X509ExtensionPtr ext(
            X509V3_EXT_i2d(NID_subject_alt_name, 0, gens.get()));
        if (ext == nullptr)
        {
            lg2::error("Error creating subjectAltName extension");
            elog<InternalFailure>();
        }

        X509ExtListPtr extlist(sk_X509_EXTENSION_new_null());
        sk_X509_EXTENSION_push(extlist.get(), ext.release());
        if (!X509_REQ_add_extensions(x509Req.get(), extlist.get()))
        {
            lg2::error("Error adding subjectAltName extension to the request");
            elog<InternalFailure>();
        }
    }
    else
    {
        lg2::error("Empty string is not allowed in SubjectAltNAme");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("CSR"),
                              Argument::ARGUMENT_VALUE("Empty"));
    }
    ret = X509_REQ_set_pubkey(x509Req.get(), pKey.get());
    if (ret == 0)
    {
        lg2::error("Error occurred while setting Public key");
        ERR_print_errors_fp(stderr);
        elog<InternalFailure>();
    }

    // Write private key to file
    writePrivateKey(pKey, defaultPrivateKeyFileName);

    // set sign key of x509 req
    ret = X509_REQ_sign(x509Req.get(), pKey.get(), EVP_sha256());
    if (ret == 0)
    {
        lg2::error("Error occurred while signing key of x509");
        ERR_print_errors_fp(stderr);
        elog<InternalFailure>();
    }

    lg2::info("Writing CSR to file");
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
        lg2::info("KeyBitLength is not given.Hence, using default KeyBitLength:"
                  "{DEFAULTKEYBITLENGTH}",
                  "DEFAULTKEYBITLENGTH", defaultKeyBitLength);
        keyBitLen = defaultKeyBitLength;
    }

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)

    // generate rsa key
    BignumPtr bne(BN_new(), ::BN_free);
    auto ret = BN_set_word(bne.get(), RSA_F4);
    if (ret == 0)
    {
        lg2::error("Error occurred during BN_set_word call");
        ERR_print_errors_fp(stderr);
        elog<InternalFailure>();
    }
    using RSAPtr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
    RSAPtr rsa(RSA_new(), ::RSA_free);
    ret = RSA_generate_key_ex(rsa.get(), keyBitLen, bne.get(), nullptr);
    if (ret != 1)
    {
        lg2::error(
            "Error occurred during RSA_generate_key_ex call: {KEYBITLENGTH}",
            "KEYBITLENGTH", keyBitLen);
        ERR_print_errors_fp(stderr);
        elog<InternalFailure>();
    }

    // set public key of x509 req
    EVPPkeyPtr pKey(EVP_PKEY_new(), ::EVP_PKEY_free);
    ret = EVP_PKEY_assign_RSA(pKey.get(), rsa.get());
    if (ret == 0)
    {
        lg2::error("Error occurred during assign rsa key into EVP");
        ERR_print_errors_fp(stderr);
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
        lg2::error("Error occurred creating EVP_PKEY_CTX from algorithm");
        ERR_print_errors_fp(stderr);
        elog<InternalFailure>();
    }

    if ((EVP_PKEY_keygen_init(ctx.get()) <= 0) ||
        (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(),
                                          static_cast<int>(keyBitLen)) <= 0))

    {
        lg2::error("Error occurred initializing keygen context");
        ERR_print_errors_fp(stderr);
        elog<InternalFailure>();
    }

    EVP_PKEY* pKey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pKey) <= 0)
    {
        lg2::error("Error occurred during generate EC key");
        ERR_print_errors_fp(stderr);
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
        lg2::info("KeyCurveId is not given. Hence using default curve id,"
                  "DEFAULTKEYCURVEID:{DEFAULTKEYCURVEID}",
                  "DEFAULTKEYCURVEID", defaultKeyCurveID);
        curId = defaultKeyCurveID;
    }

    int ecGrp = OBJ_txt2nid(curId.c_str());
    if (ecGrp == NID_undef)
    {
        lg2::error(
            "Error occurred during convert the curve id string format into NID,"
            "KEYCURVEID:{KEYCURVEID}",
            "KEYCURVEID", curId);
        elog<InternalFailure>();
    }

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)

    EC_KEY* ecKey = EC_KEY_new_by_curve_name(ecGrp);

    if (ecKey == nullptr)
    {
        lg2::error(
            "Error occurred during create the EC_Key object from NID, ECGROUP:{ECGROUP}",
            "ECGROUP", ecGrp);
        ERR_print_errors_fp(stderr);
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
        lg2::error("Error occurred during generate EC key");
        ERR_print_errors_fp(stderr);
        elog<InternalFailure>();
    }

    EVPPkeyPtr pKey(EVP_PKEY_new(), ::EVP_PKEY_free);
    ret = EVP_PKEY_assign_EC_KEY(pKey.get(), ecKey);
    if (ret == 0)
    {
        EC_KEY_free(ecKey);
        lg2::error("Error occurred during assign EC Key into EVP");
        ERR_print_errors_fp(stderr);
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
        lg2::error("Error occurred creating EVP_PKEY_CTX for params");
        ERR_print_errors_fp(stderr);
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
        lg2::error("Error occurred setting curve parameters");
        ERR_print_errors_fp(stderr);
        elog<InternalFailure>();
    }

    // Move parameters to RAII holder.
    auto pparms = holderOfKey(params);

    // Create new context for key.
    ctx.reset(EVP_PKEY_CTX_new_from_pkey(nullptr, params, nullptr));

    if (!ctx || (EVP_PKEY_keygen_init(ctx.get()) <= 0))
    {
        lg2::error("Error occurred initializing keygen context");
        ERR_print_errors_fp(stderr);
        elog<InternalFailure>();
    }

    EVP_PKEY* pKey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pKey) <= 0)
    {
        lg2::error("Error occurred during generate EC key");
        ERR_print_errors_fp(stderr);
        elog<InternalFailure>();
    }

    return holderOfKey(pKey);
#endif
}

void Manager::writePrivateKey(const EVPPkeyPtr& pKey,
                              const std::string& privKeyFileName)
{
    lg2::info("Writing private key to file");
    // write private key to file
    fs::path privKeyPath = certParentInstallPath / privKeyFileName;

    FILE* fp = std::fopen(privKeyPath.c_str(), "w");
    if (fp == nullptr)
    {
        lg2::error("Error occurred creating private key file");
        elog<InternalFailure>();
    }
    int ret = PEM_write_PrivateKey(fp, pKey.get(), nullptr, nullptr, 0, nullptr,
                                   nullptr);
    std::fclose(fp);
    if (ret == 0)
    {
        lg2::error("Error occurred while writing private key to file");
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
        lg2::error("Unable to set entry, FIELD:{FIELD}, VALUE:{VALUE}", "FIELD",
                   field, "VALUE", bytes);
        ERR_print_errors_fp(stderr);
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
        lg2::info("Removing the existing file, FILENAME:{FILENAME}", "FILENAME",
                  filePath);
        if (!fs::remove(filePath.c_str()))
        {
            lg2::error("Unable to remove the file, FILENAME:{FILENAME}",
                       "FILENAME", filePath);
            elog<InternalFailure>();
        }
    }

    FILE* fp = std::fopen(filePath.c_str(), "w");

    if (fp == nullptr)
    {
        lg2::error(
            "Error opening the file to write the CSR, FILENAME:{FILENAME}",
            "FILENAME", filePath);
        elog<InternalFailure>();
    }

    int rc = PEM_write_X509_REQ(fp, x509Req.get());
    if (!rc)
    {
        lg2::error("PEM write routine failed, FILENAME:{FILENAME}", "FILENAME",
                   filePath);
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
            lg2::error("Certificate installation path exists and it is "
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
        lg2::error(
            "Given Key bit length is not supported, GIVENKEYBITLENGTH:"
            "{GIVENKEYBITLENGTH}, SUPPORTEDKEYBITLENGTH:{SUPPORTEDKEYBITLENGTH}",
            "GIVENKEYBITLENGTH", keyBitLength, "SUPPORTEDKEYBITLENGTH",
            supportedKeyBitLength);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("KEYBITLENGTH"),
            Argument::ARGUMENT_VALUE(std::to_string(keyBitLength).c_str()));
    }
    fs::path rsaPrivateKeyFileName =
        certParentInstallPath / defaultRSAPrivateKeyFileName;

    FILE* privateKeyFile = std::fopen(rsaPrivateKeyFileName.c_str(), "r");
    if (!privateKeyFile)
    {
        lg2::error(
            "Unable to open RSA private key file to read, RSAKEYFILE:{RSAKEYFILE},"
            "ERRORREASON:{ERRORREASON}",
            "RSAKEYFILE", rsaPrivateKeyFileName, "ERRORREASON",
            strerror(errno));
        elog<InternalFailure>();
    }

    EVPPkeyPtr privateKey(
        PEM_read_PrivateKey(privateKeyFile, nullptr, nullptr, nullptr),
        ::EVP_PKEY_free);
    std::fclose(privateKeyFile);

    if (!privateKey)
    {
        lg2::error("Error occurred during PEM_read_PrivateKey call");
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
                lg2::error(
                    "Failed to remove symlink for certificate, ERR:{ERR} SYMLINK:{SYMLINK}",
                    "ERR", e, "SYMLINK", certPath.path().string());
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
            lg2::error(
                "Failed to reload or restart service, ERR:{ERR}, UNIT:{UNIT}",
                "ERR", e, "UNIT", unit);
            elog<InternalFailure>();
        }
    }
}

bool Manager::isCertificateUnique(const std::string& filePath,
                                  const Certificate* const certToDrop)
{
    if (std::any_of(
            installedCerts.begin(), installedCerts.end(),
            [&filePath, certToDrop](const std::unique_ptr<Certificate>& cert) {
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
