#include "certs_manager.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <xyz/openbmc_project/Certs/Install/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace certs
{

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using Reason = xyz::openbmc_project::Certs::Install::InvalidCertificate::REASON;

/** @brief Constructor to put object onto bus at a dbus path.
 *  @param[in] bus - Bus to attach to.
 *  @param[in] path - Path to attach at.
 *  @param[in] type - Type of the certificate.
 *  @param[in] unit - Unit consumed by this certificate.
 *  @param[in] installPath - Certificate installation path.
 */
Manager::Manager(sdbusplus::bus::bus& bus, const char* path,
                 const CertificateType& type, UnitsToRestart&& unit,
                 CertInstallPath&& installPath) :
    Ifaces(bus, path),
    bus(bus), objectPath(path), certType(type), unitToRestart(std::move(unit)),
    certInstallPath(std::move(installPath))
{
}

void Manager::install(const std::string filePath)
{
}

void Manager::delete_()
{
    // TODO: #Issue 4 when a certificate is deleted system auto generates
    // certificate file. At present we are not supporting creation of
    // certificate object for the auto-generated certificate file as
    // deletion if only applicable for REST server and Bmcweb does not allow
    // deletion of certificates
    if (certificatePtr != nullptr)
    {
        certificatePtr.reset(nullptr);
    }
}
} // namespace certs
} // namespace phosphor
