#include <experimental/filesystem>

#include "certs_manager.hpp"

#include <sdbusplus/bus.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>
#include "xyz/openbmc_project/Common/error.hpp"

namespace phosphor
{
namespace certs
{

using namespace phosphor::logging;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

void Manager::install(const std::string path)
{
    // TODO Validate the certificate file

    // Copy the certificate file
    copy(path, certPath);

    // Invoke type specific install function.
    auto iter = typeFuncMap.find(type);
    if (iter == typeFuncMap.end())
    {
        log<level::ERR>("Unsupported Type",
                        entry("RC=%s", type.c_str()));
        elog<InternalFailure>();
    }
    iter->second();
}

void Manager::serverInstall()
{
    if(!unit.empty())
    {
        reload(unit);
    }
}

void Manager::clientInstall()
{
    //Do nothing now
}

void Manager::reload(const std::string& unit)
{
    constexpr auto SYSTEMD_SERVICE = "org.freedesktop.systemd1";
    constexpr auto SYSTEMD_OBJ_PATH = "/org/freedesktop/systemd1";
    constexpr auto SYSTEMD_INTERFACE = "org.freedesktop.systemd1.Manager";

    try
    {
        auto method = bus.new_method_call(
                          SYSTEMD_SERVICE,
                          SYSTEMD_OBJ_PATH,
                          SYSTEMD_INTERFACE,
                          "ReloadUnit");

        method.append(unit, "replace");

        bus.call_noreply(method);
    }
    catch (const sdbusplus::exception::SdBusError& e)
    {
        log<level::ERR>("Failed to reload service",
                        entry("Unit=%s", unit.c_str()));
        elog<InternalFailure>();
    }
}

void Manager::copy(const std::string& src, const std::string& dst)
{
    namespace fs = std::experimental::filesystem;

    try
    {
        auto path = fs::path(dst).parent_path();

        if (!fs::is_directory(path))
        {
            fs::create_directory(path); // create dst path folder
        }
        fs::copy_file(src, dst, fs::copy_options::overwrite_existing);
    }
    catch (fs::filesystem_error& e)
    {
        log<level::ERR>("Failed to copy certificate",
                        entry("ERR=%s", e.what()),
                        entry("SRC=%s",src.c_str()),
                        entry("DST=%s",dst.c_str()));
        elog<InternalFailure>();
    }
}

} //certs
} //phosphor
