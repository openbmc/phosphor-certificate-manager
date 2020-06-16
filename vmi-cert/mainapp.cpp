#include "config.h"

#include "vmi_certs_manager.hpp"

#include <sdeventplus/event.hpp>
#include <string>

int main(int argc, char** argv)
{
    auto bus = sdbusplus::bus::new_default();
    std::string objPath = "/com/ibm/VMICertificate";

    // Add sdbusplus ObjectManager
    sdbusplus::server::manager::manager objManager(bus, objPath.c_str());

    // Get default event loop
    auto event = sdeventplus::Event::get_default();

    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    ibm::vmicert::vmiCertMgr manager(bus, event, objPath.c_str());

    // Adjusting Interface name as per std convention
    std::string busName = "com.ibm.VMICertificate";
    bus.request_name(busName.c_str());
    event.loop();
    return 0;
}
