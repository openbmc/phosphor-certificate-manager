#pragma once

#include <openssl/x509.h>

#include <filesystem>
#include <phosphor-logging/elog.hpp>
#include <xyz/openbmc_project/Certs/Certificate/server.hpp>
#include <xyz/openbmc_project/Certs/Install/server.hpp>

namespace phosphor
{
namespace certs
{
using CertificateIface = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::Certs::server::Certificate>;
using InstallIface = sdbusplus::xyz::openbmc_project::Certs::server::Install;
using CertIfaces =
    sdbusplus::server::object::object<CertificateIface, InstallIface>;

using CertificateType = std::string;
using UnitsToRestart = std::string;
using CertInstallPath = std::string;
using CertUploadPath = std::string;
using InputType = std::string;
using InstallFunc = std::function<void(const std::string&)>;

using namespace phosphor::logging;

// for placeholders
using namespace std::placeholders;
namespace fs = std::filesystem;

// Supported Types.
static constexpr auto SERVER = "server";
static constexpr auto CLIENT = "client";
static constexpr auto AUTHORITY = "authority";

// RAII support for openSSL functions.
using X509_Ptr = std::unique_ptr<X509, decltype(&::X509_free)>;

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
     */
    Certificate(sdbusplus::bus::bus& bus, const std::string& objPath,
                const CertificateType& type, const UnitsToRestart& unit,
                const CertInstallPath& installPath,
                const CertUploadPath& uploadPath);

    /** @brief Implementation for Install
     *  Replace the existing certificate file with another
     *  (possibly CA signed) Certificate file.
     *  @param[in] filePath - Certificate file path.
     */
    void install(const std::string filePath) override;

  private:
    /** @brief Load Certificate file into the X509 structre.
     *  @param[in] fileName - Certificate and key full file path.
     *  @return pointer to the X509 structure.
     */
    X509_Ptr loadCert(const std::string& filePath);

    /** @brief Public/Private key compare function.
     *         Comparing private key against certificate public key
     *         from input .pem file.
     *  @param[in] fileName - Certificate and key full file path.
     *  @return Return true if Key compare is successful,
     *          false if not
     */
    bool compareKeys(const std::string& filePath);
    /** @brief systemd unit reload or reset helper function
     *  Reload if the unit supports it and use a restart otherwise.
     *  @param[in] unit - service need to reload.
     */
    void reloadOrReset(const UnitsToRestart& unit);

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
};

} // namespace certs
} // namespace phosphor
