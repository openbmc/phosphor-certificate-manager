#pragma once

#include "watch.hpp"

#include <openssl/x509.h>

#include <filesystem>
#include <phosphor-logging/elog.hpp>
#include <xyz/openbmc_project/Certs/Certificate/server.hpp>
#include <xyz/openbmc_project/Certs/Replace/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

namespace phosphor
{
namespace certs
{
using DeleteIface = sdbusplus::xyz::openbmc_project::Object::server::Delete;
using CertificateIface = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::Certs::server::Certificate>;
using ReplaceIface = sdbusplus::xyz::openbmc_project::Certs::server::Replace;
using CertIfaces = sdbusplus::server::object::object<CertificateIface,
                                                     ReplaceIface, DeleteIface>;

using CertificateType = std::string;
using UnitsToRestart = std::string;
using CertInstallPath = std::string;
using CertUploadPath = std::string;
using InputType = std::string;
using InstallFunc = std::function<void(const std::string&)>;
using AppendPrivKeyFunc = std::function<void(const std::string&)>;
using CertWatchPtr = std::unique_ptr<Watch>;
using namespace phosphor::logging;

// for placeholders
using namespace std::placeholders;
namespace fs = std::filesystem;

class Manager; // Forward declaration for Certificate Manager.

// Supported Types.
static constexpr auto SERVER = "server";
static constexpr auto CLIENT = "client";
static constexpr auto AUTHORITY = "authority";

// RAII support for openSSL functions.
using X509_Ptr = std::unique_ptr<X509, decltype(&::X509_free)>;
using X509_STORE_CTX_Ptr =
    std::unique_ptr<X509_STORE_CTX, decltype(&::X509_STORE_CTX_free)>;

/** @class Certificate
 *  @brief OpenBMC Certificate entry implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Certs.Certificate DBus API
 *  xyz.openbmc_project.Certs.Instal DBus API
 */
class Certificate : public CertIfaces
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
     *  @param[in] unit - Units to restart after a certificate is installed
     *  @param[in] installPath - Path of the certificate to install
     *  @param[in] uploadPath - Path of the certificate file to upload
     *  @param[in] isSkipUnitReload - If true do not restart units
     *  @param[in] watchPtr - watch on self signed certificate pointer
     */
    Certificate(sdbusplus::bus::bus& bus, const std::string& objPath,
                const CertificateType& type, const UnitsToRestart& unit,
                const CertInstallPath& installPath,
                const CertUploadPath& uploadPath, bool isSkipUnitReload,
                const CertWatchPtr& watchPtr, Manager& parent);

    /** @brief Validate certificate and replace the existing certificate
     *  @param[in] filePath - Certificate file path.
     */
    void replace(const std::string filePath) override;

    /** @brief Populate certificate properties by parsing certificate file
     *  @return void
     */
    void populateProperties();

    /**
     * @brief Obtain certificate's ID.
     *
     * @return Certificate's ID.
     */
    const std::string& getCertId() const;

    /**
     * @brief Get certificate's file path.
     *
     * @return Certificate's file path.
     */
    const std::string& getCertFilePath() const;

    /**
     * @brief Rename certificate's file name.
     *
     * @param[in] newCertFilePath Target certificate's file name.
     *
     * @return Operation result.
     */
    int setCertFilePath(const std::string& newCertFilePath);

    /**
     * @brief Obtain certificate's object path
     *
     * @return certificate's object path.
     */
    const std::string& getObjectPath() const;

    /**
     * @brief Delete the certificate
     */
    void delete_() override;

  private:
    /**
     * @brief Populate certificate properties by parsing given certificate file
     *
     * @param[in] certPath   Path to certificate that should be parsed
     *
     * @return void
     */
    void populateProperties(const std::string& certPath);

    /** @brief Validate and Replace/Install the certificate file
     *  Install/Replace the existing certificate file with another
     *  (possibly CA signed) Certificate file.
     *  @param[in] filePath - Certificate file path.
     *  @param[in] isSkipUnitReload - If true do not restart units
     */
    void install(const std::string& filePath, bool isSkipUnitReload);

    /** @brief Load Certificate file into the X509 structre.
     *  @param[in] filePath - Certificate and key full file path.
     *  @return pointer to the X509 structure.
     */
    X509_Ptr loadCert(const std::string& filePath);

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

    /** @brief systemd unit reload or reset helper function
     *  Reload if the unit supports it and use a restart otherwise.
     *  @param[in] unit - service need to reload.
     */
    void reloadOrReset(const UnitsToRestart& unit);

    /**
     * @brief Generate certificate ID based on provided x509 certificate
     * structure.
     *
     * @param[in] cert - Pointer to x509 certificate structure.
     *
     * @return Certificate's ID as formatted string.
     */
    std::string generateCertId(const X509_Ptr& cert);

    /**
     * @brief Check if certificate is unique based on ID calculated with
     * generateCertId() method.
     *
     * @param[in] certId - Pointer to x509 certificate structure which needs to
     * be checked.
     *
     * @return Checking result.
     */
    bool isCertUnique(const std::string& certId);

    /**
     * @brief Prepare authority certificate's file full name (basic name and
     * extension) based on provied file name and file name extension. OpenSSL
     * puts some restrictions on the certificate file name pattern.
     * Certificate's full file name needs to consists of basic file name which
     * is certificate's subject name hash and file name extension which is an
     * integer. More over, certifiacets files names extensions must be
     * consecutive integer numbers.
     * https://www.boost.org/doc/libs/1_69_0/doc/html/boost_asio/reference/ssl__context/add_verify_path.html
     * https://www.openssl.org/docs/man1.0.2/man3/SSL_CTX_load_verify_locations.html
     *
     * @param[in] certFileName - Certificate file name.
     * @param[in] certFileNameExt - Certificate file name extension.
     *
     * @return Authority certificate's file full name extension.
     */
    std::string prepareAuthCertFileFullName(const std::string& certFileName,
                                            const std::string& certFileNameExt);

    /**
     * @brief Generate authority certificate's file name based on provided x509
     * certificate structure.
     *
     * @param[in] cert - Pointer to x509 certificate structure.
     *
     * @return Authority certificate's file name.
     */
    std::string generateAuthCertFileName(const X509_Ptr& cert);

    /**
     * @brief Generate authority certificate's file name extension based on
     * provided certificate file name. This method calls certifiacates manager
     * API to learn which extensions are currently occupied.
     *
     * @param[in] certFileName - Certificate file name.
     *
     * @return Authority certificate's file name extension.
     */
    std::string generateAuthCertFileNameExt(const std::string& certFileName);

    /**
     * @brief Get this authority certificates files directory path.
     *
     * @return Authority certificates files directory path.
     */
    std::string getAuthCertFilesDirectory();

    /**
     * @brief Get this authority certificate's file full name.
     *
     * @return Authority certificate's file full name.
     */
    std::string getAuthCertFileFullName();

    /**
     * @brief Get this authority certificate's file name.
     *
     * @return Authority certificate's file name.
     */
    std::string getAuthCertFileName();

    /**
     * @brief Get this authority certificate's file name extension.
     *
     * @return Authority certificate's file name extension.
     */
    std::string getAuthCertFileNameExt();

    /**
     * @brief Prepare authority certificate's file path based on provied file
     * name and file name extension.
     *
     * @param[in] certFileName - Certificate file name.
     * @param[in] certFileNameExt - Certificate file name extension.
     *
     * @return Authority certificate's file path.
     */
    std::string prepareAuthCertFilePath(const std::string& certFileName,
                                        const std::string& certFileNameExt);

    /**
     * @brief Generate authority certificate's file path based on provided x509
     * certificate structure.
     *
     * @param[in] cert - Pointer to x509 certificate structure.
     *
     * @return Authority certificate's file path.
     */
    std::string generateAuthCertFilePath(const X509_Ptr& cert);

    /**
     * @brief Reorder authority certificates storage.
     * OpenSSL puts some restrictions on the certificate file name pattern,
     * esspecially on files name extensions. That's why re-ordering is needed in
     * case particular certificate was deleted or repalaced.
     *
     * @return None.
     */
    void reorderAuthCertStorage();

    /**
     * @brief Generate certificate's file path based on provided x509
     * certificate structure.
     *
     * @param[in] cert - Pointer to x509 certificate structure.
     *
     * @return Certificate's file path.
     */
    std::string generateCertFilePath(const X509_Ptr& cert);

    /**
     * @brief Certificates storage clean-up.
     *
     * @param[in] newCertFilePath Certificate file name.
     *
     * @return None.
     */
    void storageCleanUp(const std::string& newCertFilePath);

    /** @brief Type specific function pointer map **/
    std::unordered_map<InputType, InstallFunc> typeFuncMap;

    /** @brief sdbusplus handler */
    sdbusplus::bus::bus& bus;

    /** @brief object path */
    std::string objectPath;

    /** @brief Type of the certificate **/
    CertificateType certType;

    /** @brief Unit name associated to the service **/
    UnitsToRestart unitToRestart;

    /** @brief Certificate file installation path **/
    CertInstallPath certInstallPath;

    /** @brief Type specific function pointer map for appending private key */
    std::unordered_map<InputType, AppendPrivKeyFunc> appendKeyMap;

    /** @brief Certificate file create/update watch */
    const CertWatchPtr& certWatchPtr;

    /** @brief Stores certificate ID */
    std::string certificateId;

    /** @brief Stores certificate's file path
     */
    std::string certificateFilePath;

    /** @brief Reference to Certificate Manager */
    Manager& manager;
};

} // namespace certs
} // namespace phosphor
