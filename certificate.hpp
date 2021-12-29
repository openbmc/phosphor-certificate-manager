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
    Authority,
    Server,
    Client,
    Unsupported,
};

inline constexpr const char* certificateTypeToString(CertificateType type)
{
    switch (type)
    {
        case CertificateType::Authority:
            return "authority";
        case CertificateType::Server:
            return "server";
        case CertificateType::Client:
            return "client";
        default:
            return "unsupported";
    }
}

inline constexpr CertificateType stringToCertificateType(std::string_view type)
{
    if (type == "authority")
    {
        return CertificateType::Authority;
    }
    if (type == "server")
    {
        return CertificateType::Server;
    }
    if (type == "client")
    {
        return CertificateType::Client;
    }
    return CertificateType::Unsupported;
}

class Manager; // Forward declaration for Certificate Manager.

/** @class Certificate
 *  @brief OpenBMC Certificate entry implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Certs.Certificate DBus API
 *  xyz.openbmc_project.Certs.Install DBus API
 */
class Certificate
    : public sdbusplus::server::object::object<
          sdbusplus::xyz::openbmc_project::Certs::server::Certificate,
          sdbusplus::xyz::openbmc_project::Certs::server::Replace,
          sdbusplus::xyz::openbmc_project::Object::server::Delete>
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
    Certificate(sdbusplus::bus::bus& bus, const std::string& objPath,
                CertificateType type, const std::string& installPath,
                const std::string& uploadPath, Watch* watchPtr,
                Manager& parent);

    /** @brief Validate and Replace/Install the certificate file
     *  Install/Replace the existing certificate file with another
     *  (possibly CA signed) Certificate file.
     *  @param[in] filePath - Certificate file path.
     */
    void install(const std::string& filePath);

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

    /** @brief Load Certificate file into the X509 structure.
     *  @param[in] filePath - Certificate and key full file path.
     *  @return pointer to the X509 structure.
     */
    std::unique_ptr<X509, decltype(&::X509_free)>
        loadCert(const std::string& filePath);

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
     * @brief Generate file name which is unique in the provided directory.
     *
     * @param[in] directoryPath - Directory path.
     *
     * @return File path.
     */
    std::string generateUniqueFilePath(const std::string& directoryPath);

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
    std::unordered_map<CertificateType, std::function<void(const std::string&)>>
        typeFuncMap;

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
    std::unordered_map<CertificateType, std::function<void(const std::string&)>>
        appendKeyMap;

    /** @brief Certificate file create/update watch */
    Watch* certWatchPtr;

    /** @brief Reference to Certificate Manager */
    Manager& manager;
};

} // namespace phosphor::certs
