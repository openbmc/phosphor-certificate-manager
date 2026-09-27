#include "config.h"

#include "certs_manager.hpp"

#include "x509_utils.hpp"

#include <fcntl.h>
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
#include <system_error>
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

/**
 * @brief Recursively removes a path when it goes out of scope, unless
 * release() has been called. Errors are logged, never thrown.
 */
class ScopedRemove
{
  public:
    explicit ScopedRemove(fs::path path) : path(std::move(path)) {}
    ScopedRemove(const ScopedRemove&) = delete;
    ScopedRemove& operator=(const ScopedRemove&) = delete;
    ~ScopedRemove()
    {
        if (path.empty())
        {
            return;
        }
        std::error_code ec;
        fs::remove_all(path, ec);
        if (ec)
        {
            lg2::error("Failed to clean up, PATH:{PATH}, ERR:{ERR}", "PATH",
                       path, "ERR", ec.message());
        }
    }
    void release()
    {
        path.clear();
    }

  private:
    fs::path path;
};

/**
 * @brief Creates a new, uniquely named directory under |parent| (created if
 * missing) using mkdtemp(3).
 */
fs::path makeTempDir(const fs::path& parent)
{
    std::error_code ec;
    fs::create_directories(parent, ec);
    std::string pathTemplate = (parent / "XXXXXX").string();
    if (::mkdtemp(pathTemplate.data()) == nullptr)
    {
        int err = errno;
        lg2::error("Failed to create staging directory, DIR:{DIR}, ERR:{ERR}",
                   "DIR", parent, "ERR", std::strerror(err));
        elog<InternalFailure>();
    }
    return pathTemplate;
}

/**
 * @brief Creates a new, empty, uniquely named hidden file ".|name|.XXXXXX" in
 * |dir| using mkstemp(3).
 */
fs::path makeTempFile(const fs::path& dir, const std::string& name)
{
    std::string pathTemplate = (dir / ("." + name + ".XXXXXX")).string();
    int fd = ::mkstemp(pathTemplate.data());
    if (fd < 0)
    {
        int err = errno;
        lg2::error("Failed to create temporary file, DIR:{DIR}, ERR:{ERR}",
                   "DIR", dir, "ERR", std::strerror(err));
        elog<InternalFailure>();
    }
    ::close(fd);
    return pathTemplate;
}

/**
 * @brief fsync(2)s a regular file so its data is durable before it is renamed
 * into place. Throws InternalFailure on error (e.g. EIO / ENOSPC).
 */
void syncFile(const fs::path& path)
{
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0 || ::fsync(fd) != 0)
    {
        int err = errno;
        if (fd >= 0)
        {
            ::close(fd);
        }
        lg2::error("Failed to sync file, FILE:{FILE}, ERR:{ERR}", "FILE", path,
                   "ERR", std::strerror(err));
        elog<InternalFailure>();
    }
    ::close(fd);
}

/**
 * @brief Best-effort fsync(2) of a directory so a rename in it is durable.
 * Some filesystems don't support this, so failures are only logged.
 */
void syncDirectory(const fs::path& path)
{
    int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0 || ::fsync(fd) != 0)
    {
        lg2::warning("Failed to sync directory, DIR:{DIR}, ERR:{ERR}", "DIR",
                     path, "ERR", std::strerror(errno));
    }
    if (fd >= 0)
    {
        ::close(fd);
    }
}

/**
 * @brief Atomically exchanges two existing paths with
 * renameat2(RENAME_EXCHANGE).
 *
 * @return 0 on success, otherwise the errno value.
 */
int exchangePaths(const fs::path& first, const fs::path& second)
{
    if (::renameat2(AT_FDCWD, first.c_str(), AT_FDCWD, second.c_str(),
                    RENAME_EXCHANGE) == 0)
    {
        return 0;
    }
    return errno;
}

/**
 * @brief Whether a renameat2() errno means the filesystem or kernel doesn't
 * support the requested flag (e.g. JFFS2 without the RENAME_EXCHANGE patch
 * returns EINVAL), as opposed to a real failure.
 */
bool isRenameFlagUnsupported(int err)
{
    return err == EINVAL || err == ENOSYS || err == EOPNOTSUPP;
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

std::vector<sdbusplus::object_path> Manager::installAll(
    const std::string filePath)
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

    return installAuthoritiesList(filePath, /*replace=*/false);
}

std::vector<sdbusplus::object_path> Manager::replaceAll(std::string filePath)
{
    if (certType != CertificateType::authority)
    {
        elog<NotAllowed>(NotAllowedReason(
            "The ReplaceAll interface is only allowed for "
            "Authority certificates"));
    }

    // The existing certificates are only dropped once the new list has been
    // validated and committed, so a bad or failed replace leaves them intact.
    return installAuthoritiesList(filePath, /*replace=*/true);
}

std::vector<sdbusplus::object_path> Manager::installAuthoritiesList(
    const std::string& filePath, bool replace)
{
    fs::path sourceFile(filePath);
    if (!fs::exists(sourceFile))
    {
        lg2::error("File is Missing, FILE:{FILE}", "FILE", filePath);
        elog<InternalFailure>();
    }

    // 1. Stage: snapshot the source into volatile storage and validate it
    //    there. Nothing on persistent storage is touched in this phase.
    fs::path stagingDir = makeTempDir(stagingRoot());
    ScopedRemove stagingGuard(stagingDir);
    fs::path stagedList = stagingDir / defaultAuthoritiesListFileName;
    Certificate::copyCertificate(sourceFile, stagedList);

    std::vector<std::string> authorities = splitCertificates(stagedList);
    if (authorities.size() > maxNumAuthorityCertificates)
    {
        elog<NotAllowed>(NotAllowedReason("Certificates limit reached"));
    }
    X509StorePtr x509Store = getX509Store(stagedList);
    for (const auto& authority : authorities)
    {
        auto cert = parseCert(authority);
        validateCertificateAgainstStore(*x509Store, *cert);
        validateCertificateStartDate(*cert);
        validateCertificateInSSLContext(*cert);
    }

    lg2::info("Starts authority list install");

    // 2. Commit: copy the staged list to a temporary file next to the final
    //    one (same filesystem) and flush it, then swap it into place.
    //    - Preferred: renameat2(RENAME_EXCHANGE). The new list atomically takes
    //      the final name and the previous list moves to the temporary name,
    //      where it is kept until publishing succeeds so we can roll back.
    //      (gBMC kernels carry a JFFS2 patch adding RENAME_EXCHANGE.)
    //    - Fallback: rename(2), which atomically replaces the previous list.
    //    Either way, after a crash or failure at any point the final name holds
    //    either the complete old list or the complete new one. The temporary
    //    name is removed by the guard, or at the next boot by
    //    restoreAuthoritiesList().
    const fs::path installDir(certInstallPath);
    const fs::path listFile = installDir / defaultAuthoritiesListFileName;
    fs::path tmpList = makeTempFile(installDir, defaultAuthoritiesListFileName);
    ScopedRemove tmpListGuard(tmpList);
    Certificate::copyCertificate(stagedList, tmpList);
    syncFile(tmpList);

    bool exchanged = false;
    if (fs::exists(listFile))
    {
        if (int err = exchangePaths(tmpList, listFile); err == 0)
        {
            exchanged = true;
        }
        else if (err == ENOENT)
        {
            // The list went away since we checked; nothing to exchange with.
        }
        else if (isRenameFlagUnsupported(err))
        {
            lg2::info("RENAME_EXCHANGE unsupported, falling back to rename, "
                      "DIR:{DIR}, ERR:{ERR}",
                      "DIR", installDir, "ERR", std::strerror(err));
        }
        else
        {
            lg2::error("Failed to exchange authorities list, SRC:{SRC}, "
                       "DST:{DST}, ERR:{ERR}",
                       "SRC", tmpList, "DST", listFile, "ERR",
                       std::strerror(err));
            elog<InternalFailure>();
        }
    }
    if (!exchanged)
    {
        if (std::error_code ec; fs::rename(tmpList, listFile, ec), ec)
        {
            lg2::error("Failed to commit authorities list, SRC:{SRC}, "
                       "DST:{DST}, ERR:{ERR}",
                       "SRC", tmpList, "DST", listFile, "ERR", ec.message());
            elog<InternalFailure>();
        }
        tmpListGuard.release();
    }
    // When exchanged, tmpListGuard now owns the previous list and removes it
    // once we are done with it.
    syncDirectory(installDir);

    // 3. Publish: swap the in-memory certificates. The list on disk is the
    //    source of truth from here on; the individual certificate files and
    //    symlinks are derived from it and are regenerated at boot.
    const uint64_t previousFirstId = certIdCounter - installedCerts.size();
    installedCerts.clear();
    if (replace)
    {
        certIdCounter = 1;
    }
    storageUpdate();
    try
    {
        createAuthorityCertificates(authorities, *x509Store,
                                    /*restore=*/false);
    }
    catch (...)
    {
        if (exchanged && exchangePaths(tmpList, listFile) == 0)
        {
            // Previous list is back in place; the new one is at the
            // temporary name and will be removed by tmpListGuard.
            syncDirectory(installDir);
            lg2::error("Failed to create certificate objects; rolled back to "
                       "the previous authorities list");
            try
            {
                certIdCounter = previousFirstId;
                std::vector<std::string> previous = splitCertificates(listFile);
                if (!previous.empty())
                {
                    X509StorePtr previousStore = getX509Store(listFile);
                    createAuthorityCertificates(previous, *previousStore,
                                                /*restore=*/true);
                }
            }
            catch (const std::exception& e)
            {
                lg2::error("Failed to restore previous certificate objects; "
                           "they will be recreated on restart, ERR:{ERR}",
                           "ERR", e);
            }
        }
        else
        {
            lg2::error("Authorities list committed but certificate objects "
                       "could not be created; they will be recreated on "
                       "restart");
        }
        throw;
    }

    std::vector<sdbusplus::object_path> objects;
    for (const auto& certificate : installedCerts)
    {
        objects.emplace_back(certificate->getObjectPath());
    }

    lg2::info("Finishes authority list install; reload units starts");
    reloadOrReset(unitToRestart);
    return objects;
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
            commit<InternalFailure>();
            exit(EXIT_FAILURE);
        }
        catch (const InvalidArgument& e)
        {
            // commit the error reported in child process and exit
            // Callback method from SDEvent Loop looks for exit status
            commit<InvalidArgument>();
            exit(EXIT_FAILURE);
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
            restoreAuthoritiesList(authoritiesListFilePath);
            return;
        }

        for (auto& path : fs::directory_iterator(certInstallPath))
        {
            try
            {
                // Assume here any regular file located in certificate directory
                // contains certificates body. Do not want to use soft links
                // would add value.
                // Skip (and remove) a temporary file left behind by an
                // authorities list commit that was interrupted before rename.
                if (path.path().filename().string().starts_with(
                        std::string(".") + defaultAuthoritiesListFileName +
                        "."))
                {
                    std::error_code ec;
                    fs::remove(path.path(), ec);
                    continue;
                }
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

void Manager::restoreAuthoritiesList(const fs::path& authoritiesListFilePath)
{
    // Remove everything other than the authorities list: individual
    // certificates and symlinks from the previous boot (regenerated below)
    // and any staging directory orphaned by an interrupted installAll().
    // Collect first so the directory is not modified while iterating. This is
    // best-effort: on a read-only or full filesystem we still want to restore
    // from the list rather than fail the whole manager.
    std::vector<fs::path> staleEntries;
    for (const auto& entry : fs::directory_iterator(certInstallPath))
    {
        if (entry.path() != authoritiesListFilePath)
        {
            staleEntries.emplace_back(entry.path());
        }
    }
    for (const auto& path : staleEntries)
    {
        std::error_code ec;
        fs::remove_all(path, ec);
        if (ec)
        {
            lg2::error("Failed to remove stale entry, PATH:{PATH}, ERR:{ERR}",
                       "PATH", path, "ERR", ec.message());
        }
    }

    // Unlike installAll(), do not stage a copy of the authorities list: it is
    // already in its final location and we are not changing it. Staging would
    // transiently need twice the list's size on persistent storage on every
    // boot, and leak the copy if the write fails part way.
    std::vector<std::string> authorities =
        splitCertificates(authoritiesListFilePath);
    if (authorities.size() > maxNumAuthorityCertificates)
    {
        lg2::error(
            "Persisted authorities list exceeds the limit, COUNT:{COUNT}",
            "COUNT", authorities.size());
        elog<NotAllowed>(NotAllowedReason("Certificates limit reached"));
    }

    lg2::info("Restoring authority list");

    if (!authorities.empty())
    {
        X509StorePtr x509Store = getX509Store(authoritiesListFilePath);
        createAuthorityCertificates(authorities, *x509Store, /*restore=*/true);
    }
    else
    {
        installedCerts.clear();
    }

    lg2::info("Finishes authority list restore; reload units starts");
    reloadOrReset(unitToRestart);
}

void Manager::createAuthorityCertificates(
    const std::vector<std::string>& authorities, X509_STORE& x509Store,
    bool restore)
{
    std::vector<std::unique_ptr<Certificate>> certificates;
    uint64_t idCounter = certIdCounter;
    for (const auto& authority : authorities)
    {
        std::string certObjectPath =
            objectPath + '/' + std::to_string(idCounter);
        // Certificates are written straight into the install directory. If
        // one fails, the ones already built are destroyed as the exception
        // unwinds, which removes their files again.
        certificates.emplace_back(std::make_unique<Certificate>(
            bus, certObjectPath, certType, certInstallPath, x509Store,
            authority, certWatchPtr.get(), *this, restore));
        idCounter++;
    }

    installedCerts = std::move(certificates);
    certIdCounter = idCounter;
}

std::filesystem::path Manager::stagingRoot() const
{
    return defaultStagingDir;
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
