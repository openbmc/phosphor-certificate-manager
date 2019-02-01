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
using InvalidCertificate =
    sdbusplus::xyz::openbmc_project::Certs::Install::Error::InvalidCertificate;
using Reason = xyz::openbmc_project::Certs::Install::InvalidCertificate::REASON;

void Manager::install(const std::string filePath)
{
    log<level::INFO>("Manager install certificate",
                     entry("FILEPATH=%s", filePath.c_str()));
    // Supporting only 1 certificate, user can choose to replace
    // existing certificate by using replace certificate
    if (certificatePtr != nullptr)
    {
        elog<InvalidCertificate>(Reason("Certificate already exist"));
    }
    auto certObjectPath = objectPath + '/' + "1";
    certificatePtr = std::make_unique<Certificate>(
        bus, certObjectPath, certType, unitToRestart, certInstallPath, filePath,
        true);
}

void Manager::delete_()
{
    try
    {
        if (certificatePtr != nullptr)
        {
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
