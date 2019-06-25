#pragma once

#include "key_handler.hpp"
#include "watch.hpp"

#include <openssl/x509.h>

#include <xyz/openbmc_project/Certs/Certificate/server.hpp>
#include <xyz/openbmc_project/Certs/Replace/server.hpp>
namespace phosphor
{
namespace certs
{
using CertificateIface = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::Certs::server::Certificate>;
using ReplaceIface = sdbusplus::xyz::openbmc_project::Certs::server::Replace;
using CertIfaces =
    sdbusplus::server::object::object<CertificateIface, ReplaceIface>;

using CertificateType = std::string;
using UnitsToRestart = std::string;
using CertInstallPath = std::string;

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
    virtual ~Certificate() = default;

    /** @brief Constructor for the Certificate Object
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Object path to attach to
     *  @param[in] type - Type of the certificate
     *  @param[in] unit - Units to restart after a certificate is installed
     *  @param[in] installPath - Path of the certificate to install
     *  @param[in] uploadPath - Path of the certificate file to upload
     */
    Certificate(sdbusplus::bus::bus& bus, sdeventplus::Event& event,
                const std::string& objPath, const CertificateType& type,
                const UnitsToRestart& unit, const CertInstallPath& installPath);

    /** @brief Validate certificate and replace the existing certificate
     *  @param[in] filePath - Certificate file path.
     */
    void replace(const std::string filePath) override;

    /** @brief systemd unit reload or reset helper function
     *  Reload if the unit supports it and use a restart otherwise.
     */
    void reloadOrReset();

  private:
    /** @brief Validate and Replace/Install the certificate file
     *  Install/Replace the existing certificate file with another
     *  (possibly CA signed) Certificate file.
     *  @param[in] filePath - Certificate file path.
     *  @param[in] isSkipUnitReload - If true do not restart units
     */
    void install(const std::string& filePath, bool isSkipUnitReload);

    /** @brief Populate certificate properties by parsing certificate file
     *  @return void
     */
    void populateProperties();

    /** @brief sdbusplus handler */
    sdbusplus::bus::bus& bus;

    /** @brief sd event handler */
    sdeventplus::Event& event;

    /** @brief object path */
    std::string objectPath;

    /** @brief Type of the certificate */
    CertificateType certType;

    /** @brief Unit name associated to the service */
    UnitsToRestart unitToRestart;

    /** @brief Certificate file installation path */
    CertInstallPath certInstallPath;

    /** @brief watch on certificate file */
    std::unique_ptr<Watch> modifyWatchPtr = nullptr;

    /** @brief helper class to validate the certificates */
    KeyHandler keyHandler;
};

} // namespace certs
} // namespace phosphor
