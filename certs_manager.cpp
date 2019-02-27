#include "certs_manager.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <xyz/openbmc_project/Certs/Install/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
namespace phosphor
{
namespace certs
{

using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using InvalidCertificate =
    sdbusplus::xyz::openbmc_project::Certs::Install::Error::InvalidCertificate;
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
    if (fs::exists(certInstallPath))
    {
        try
        {
            auto certObjectPath = objectPath + '/' + "1";
            certificatePtr = std::make_unique<Certificate>(
                bus, certObjectPath, certType, unitToRestart, certInstallPath,
                certInstallPath);
            certificatePtr->install(certInstallPath);
        }
        catch (const InternalFailure& e)
        {
            certificatePtr.reset(nullptr);
            report<InternalFailure>();
        }
        catch (const InvalidCertificate& e)
        {
            certificatePtr.reset(nullptr);
            report<InvalidCertificate>(
                Reason("Existing certificate file is corrupted"));
        }
    }
}

void Manager::install(const std::string filePath)
{
    using Argument = xyz::openbmc_project::Common::NotAllowed;
    log<level::INFO>("Manager install certificate",
                     entry("FILEPATH=%s", filePath.c_str()));
    // TODO: Issue#3 At present supporting only one certificate to be
    // uploaded this need to be revisited to support multiple
    // certificates
    if (certificatePtr != nullptr)
    {
        elog<NotAllowed>(Argument::REASON("Certificate already exist"));
    }
    try
    {
        auto certObjectPath = objectPath + '/' + "1";
        certificatePtr = std::make_unique<Certificate>(
            bus, certObjectPath, certType, unitToRestart, certInstallPath,
            filePath);
        certificatePtr->install(filePath);
    }
    catch (const InternalFailure& e)
    {
        certificatePtr.reset(nullptr);
        throw;
    }
    catch (const InvalidCertificate& e)
    {
        certificatePtr.reset(nullptr);
        throw;
    }
}

void Manager::delete_()
{
    try
    {
        if (certificatePtr != nullptr)
        {
            if (!fs::remove(certInstallPath))
            {
                log<level::INFO>("Certificate file not found!",
                                 entry("PATH=%s", certInstallPath.c_str()));
            }
            else if (!unitToRestart.empty())
            {
                certificatePtr->reloadOrReset(unitToRestart);
            }
            certificatePtr.reset(nullptr);
        }
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to delete certificate",
                        entry("UNIT=%s", unitToRestart.c_str()),
                        entry("ERR=%s", e.what()),
                        entry("PATH=%s", certInstallPath.c_str()));
        elog<InternalFailure>();
    }
}
} // namespace certs
} // namespace phosphor
