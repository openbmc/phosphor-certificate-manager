#include "config.h"

#include "ca_certs_manager.hpp"

#include <sdeventplus/event.hpp>
#include <string>

int main(int argc, char** argv)
{
    auto bus = sdbusplus::bus::new_default();
    std::string objPath = "/xyz/openbmc_project/certs";

    // Add sdbusplus ObjectManager
    sdbusplus::server::manager::manager objManager(bus, objPath.c_str());

    // Get default event loop
    auto event = sdeventplus::Event::get_default();

    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    ca::cert::CACertMgr manager(bus, event, objPath.c_str());

    std::string busName = "xyz.openbmc_project.Certs.ca.authority.Manager";
    bus.request_name(busName.c_str());
    event.loop();
    return 0;
}
