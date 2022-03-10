/**
 * Copyright © 2018 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"

#include "argument.hpp"
#include "certificate.hpp"
#include "certs_manager.hpp"

#include <systemd/sd-event.h>

#include <cctype>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdeventplus/event.hpp>
#include <string>
#include <utility>

inline std::string capitalize(const std::string& s)
{
    std::string res = s;
    if (!res.empty())
    {
        res[0] = std::toupper(res[0]);
    }
    return res;
}

int main(int argc, char** argv)
{
    phosphor::certs::Arguments arguments;
    if (phosphor::certs::processArguments(argc, argv, arguments) != 0)
    {
        std::exit(EXIT_FAILURE);
    }

    auto bus = sdbusplus::bus::new_default();
    auto objPath = std::string(objectNamePrefix) + '/' + arguments.typeStr +
                   '/' + arguments.endpoint;
    // Add sdbusplus ObjectManager
    sdbusplus::server::manager::manager objManager(bus, objPath.c_str());

    // Get default event loop
    auto event = sdeventplus::Event::get_default();

    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    phosphor::certs::Manager manager(
        bus, event, objPath.c_str(),
        phosphor::certs::stringToCertificateType(arguments.typeStr),
        arguments.unit, arguments.path);

    // Adjusting Interface name as per std convention
    auto busName = std::string(busNamePrefix) + '.' +
                   capitalize(arguments.typeStr) + '.' +
                   capitalize(arguments.endpoint);
    bus.request_name(busName.c_str());
    event.loop();
    return 0;
}
