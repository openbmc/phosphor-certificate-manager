#include "config.h"

#include "ca_certs_manager.hpp"

#include <sdbusplus/server/manager.hpp>

#include <string>

int main()
{
    auto bus = sdbusplus::bus::new_default();
    static constexpr auto objPath = "/xyz/openbmc_project/certs/ca";

    // Add sdbusplus ObjectManager
    sdbusplus::server::manager_t objManager(bus, objPath);

    ca::cert::CACertMgr manager(bus, objPath);

    std::string busName = "xyz.openbmc_project.Certs.ca.authority.Manager";
    bus.request_name(busName.c_str());
    bus.process_loop();
    return 0;
}
