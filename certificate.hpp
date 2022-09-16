#pragma once

#include "watch.hpp"

#include <openssl/ossl_typ.h>
#include <openssl/x509.h>

#include <functional>
#include <memory>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <string_view>
#include <unordered_map>
#include <xyz/openbmc_project/Certs/Certificate/server.hpp>
#include <xyz/openbmc_project/Certs/Replace/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

namespace phosphor::certs
{

// Certificate types
enum class CertificateType
{
    authority,
    server,
    client,
    unsupported,
};

inline constexpr const char* certificateTypeToString(CertificateType type)
{
    switch (type)
    {
        case CertificateType::authority:
            return "authority";
        case CertificateType::server:
            return "server";
        case CertificateType::client:
            return "client";
        default:
            return "unsupported";
    }
}

inline constexpr CertificateType stringToCertificateType(std::string_view type)
{
    if (type == "authority")
    {
        return CertificateType::authority;
    }
    if (type == "server")
    {
        return CertificateType::server;
    }
    if (type == "client")
    {
        return CertificateType::client;
    }
    return CertificateType::unsupported;
}

namespace internal
{
using CertificateInterface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Certs::server::Certificate,
    sdbusplus::xyz::openbmc_project::Certs::server::Replace,
    sdbusplus::xyz::openbmc_project::Object::server::Delete>;
using InstallFunc = std::function<void(const std::string&)>;
using AppendPrivKeyFunc = std::function<void(const std::string&)>;
using X509Ptr = std::unique_ptr<X509, decltype(&::X509_free)>;
} // namespace internal

class Manager; // Forward declaration for Certificate Manager.

/** @class Certificate
 *  @brief OpenBMC Certificate entry implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Certs.Certificate DBus API
 *  xyz.openbmc_project.Certs.Install DBus API
 */
class Certificate : public internal::CertificateInterface
{
  public:
    Certificate() = delete;
    Certificate(const Certificate&) = delete;
    Certificate& operator=(const Certificate&) = delete;
    Certificate(Certificate&&) = delete;
    Certificate& operator=(Certificate&&) = delete;
    virtual ~Certificate();

    /** @brief Constructor for the Certificate Object
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Object path to attach to
     *  @param[in] type - Type of the certificate
     *  @param[in] installPath - Path of the certificate to install
     *  @param[in] uploadPath - Path of the certificate file to upload
     *  @param[in] watchPtr - watch on self signed certificate
     *  @param[in] parent - the manager that owns the certificate
     */
    Certificate(sdbusplus::bus_t& bus, const std::string& objPath,
                CertificateType type, const std::string& installPath,
                const std::string& uploadPath, Watch* watch, Manager& parent);

    /** @brief Constructor for the Certificate Object; a variant for authorities
     * list install
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Object path to attach to
     *  @param[in] type - Type of the certificate
     *  @param[in] installPath - Path of the certificate to install
     *  @param[in] x509Store - an initialized X509 store used for certificate
     * validation; Certificate object doesn't own it
     *  @param[in] pem - Content of the certificate file to upload; it shall be
     * a single PEM encoded x509 certificate
     *  @param[in] watchPtr - watch on self signed certificate
     *  @param[in] parent - Pointer to the manager which owns the constructed
     * Certificate object
     */
    Certificate(sdbusplus::bus_t& bus, const std::string& objPath,
                const CertificateType& type, const std::string& installPath,
                X509_STORE& x509Store, const std::string& pem, Watch* watchPtr,
                Manager& parent);

    /** @brief Validate and Replace/Install the certificate file
     *  Install/Replace the existing certificate file with another
     *  (possibly CA signed) Certificate file.
     *  @param[in] filePath - Certificate file path.
     */
    void install(const std::string& filePath);

    /** @brief Validate and Replace/Install the certificate file
     *  Install/Replace the existing certificate file with another
     *  (possibly CA signed) Certificate file.
     *  @param[in] x509Store - an initialized X509 store used for certificate
     * validation; Certificate object doesn't own it
     *  @param[in] pem - a string buffer which stores a PEM encoded certificate.
     */
    void install(X509_STORE& x509Store, const std::string& pem);

    /** @brief Validate certificate and replace the existing certificate
     *  @param[in] filePath - Certificate file path.
     */
    void replace(const std::string filePath) override;

    /** @brief Populate certificate properties by parsing certificate file
     */
    void populateProperties();

    /**
     * @brief Obtain certificate ID.
     *
     * @return Certificate ID.
     */
    std::string getCertId() const;

    /**
     * @brief Check if provided certificate is the same as the current one.
     *
     * @param[in] certPath - File path for certificate to check.
     *
     * @return Checking result. Return true if certificates are the same,
     *         false if not.
     */
    bool isSame(const std::string& certPath);

    /**
     * @brief Update certificate storage.
     */
    void storageUpdate();

    /**
     * @brief Delete the certificate
     */
    void delete_() override;

    /**
     * @brief Generate file name which is unique in the provided directory.
     *
     * @param[in] directoryPath - Directory path.
     *
     * @return File path.
     */
    static std::string generateUniqueFilePath(const std::string& directoryPath);

    /**
     * @brief Copies the certificate from sourceFilePath to installFilePath
     *
     * @param[in] sourceFilePath - Path to the source file.
     * @param[in] certFilePath - Path to the destination file.
     *
     * @return void
     */
    static void copyCertificate(const std::string& certSrcFilePath,
                                const std::string& certFilePath);

    /**
     * @brief Returns the associated dbus object path.
     */
    std::string getObjectPath();

    /**
     * @brief Returns the associated cert file path.
     */
    std::string getCertFilePath();

    /** @brief: Set the data member |certFilePath| to |path|
     */
    void setCertFilePath(const std::string& path);

    /** @brief: Set the data member |certInstallPath| to |path|
     */
    void setCertInstallPath(const std::string& path);

  private:
    /**
     * @brief Populate certificate properties by parsing given certificate
     * object
     *
     * @param[in] cert The given certificate object
     *
     * @return void
     */
    void populateProperties(X509& cert);

    /** @brief Check and append private key to the certificate file
     *         If private key is not present in the certificate file append the
     *         certificate file with private key existing in the system.
     *  @param[in] filePath - Certificate and key full file path.
     *  @return void.
     */
    void checkAndAppendPrivateKey(const std::string& filePath);

    /** @brief Public/Private key compare function.
     *         Comparing private key against certificate public key
     *         from input .pem file.
     *  @param[in] filePath - Certificate and key full file path.
     *  @return Return true if Key compare is successful,
     *          false if not
     */
    bool compareKeys(const std::string& filePath);

    /**
     * @brief Generate authority certificate file path corresponding with
     * OpenSSL requirements.
     *
     * Prepare authority certificate file path for provided certificate.
     * OpenSSL puts some restrictions on the certificate file name pattern.
     * Certificate full file name needs to consists of basic file name which
     * is certificate subject name hash and file name extension which is an
     * integer. More over, certificates files names extensions must be
     * consecutive integer numbers in case many certificates with the same
     * subject name.
     * https://www.boost.org/doc/libs/1_69_0/doc/html/boost_asio/reference/ssl__context/add_verify_path.html
     * https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_load_verify_locations.html
     *
     * @param[in] certSrcFilePath - Certificate source file path.
     * @param[in] certDstDirPath - Certificate destination directory path.
     *
     * @return Authority certificate file path.
     */
    std::string generateAuthCertFileX509Path(const std::string& certSrcFilePath,
                                             const std::string& certDstDirPath);

    /**
     * @brief Generate authority certificate file path based on provided
     * certificate source file path.
     *
     * @param[in] certSrcFilePath - Certificate source file path.
     *
     * @return Authority certificate file path.
     */
    std::string generateAuthCertFilePath(const std::string& certSrcFilePath);

    /**
     * @brief Generate certificate file path based on provided certificate
     * source file path.
     *
     * @param[in] certSrcFilePath - Certificate source file path.
     *
     * @return Certificate file path.
     */
    std::string generateCertFilePath(const std::string& certSrcFilePath);

    /** @brief Type specific function pointer map */
    std::unordered_map<CertificateType, internal::InstallFunc> typeFuncMap;

    /** @brief object path */
    std::string objectPath;

    /** @brief Type of the certificate */
    CertificateType certType;

    /** @brief Stores certificate ID */
    std::string certId;

    /** @brief Stores certificate file path */
    std::string certFilePath;

    /** @brief Certificate file installation path */
    std::string certInstallPath;

    /** @brief Type specific function pointer map for appending private key */
    std::unordered_map<CertificateType, internal::AppendPrivKeyFunc>
        appendKeyMap;

    /** @brief Certificate file create/update watch
     * Note that Certificate object doesn't own the pointer
     */
    Watch* certWatch;

    /** @brief Reference to Certificate Manager */
    Manager& manager;
};

} // namespace phosphor::certs
