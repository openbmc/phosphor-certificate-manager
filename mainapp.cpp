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

#include <stdlib.h>
#include <systemd/sd-event.h>

#include <cctype>
#include <iostream>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdeventplus/event.hpp>
#include <string>
#include <utility>

static void ExitWithError(const char* err, char** argv)
{
    phosphor::certs::util::ArgumentParser::usage(argv);
    std::cerr << std::endl;
    std::cerr << "ERROR: " << err << std::endl;
    exit(EXIT_FAILURE);
}

inline void capitalize(std::string& s)
{
    s[0] = std::toupper(s[0]);
}

int main(int argc, char** argv)
{
    // Read arguments.
    auto options = phosphor::certs::util::ArgumentParser(argc, argv);

    // Parse arguments
    auto type = (options)["type"];
    if ((type == phosphor::certs::util::ArgumentParser::empty_string) ||
        phosphor::certs::stringToCertificateType(type) ==
            phosphor::certs::CertificateType::Unsupported)
    {
        ExitWithError("type not specified or invalid.", argv);
    }

    auto endpoint = (options)["endpoint"];
    if (endpoint == phosphor::certs::util::ArgumentParser::empty_string)
    {
        ExitWithError("endpoint not specified.", argv);
    }

    auto path = (options)["path"];
    if (path == phosphor::certs::util::ArgumentParser::empty_string)
    {
        ExitWithError("path not specified.", argv);
    }

    // unit is an optional parameter
    auto unit = (options)["unit"];
    auto bus = sdbusplus::bus::new_default();
    auto objPath = std::string(objectNamePrefix) + '/' + type + '/' + endpoint;

    // Add sdbusplus ObjectManager
    sdbusplus::server::manager::manager objManager(bus, objPath.c_str());

    // Get default event loop
    auto event = sdeventplus::Event::get_default();

    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    phosphor::certs::Manager manager(
        bus, event, objPath.c_str(),
        phosphor::certs::stringToCertificateType(type), std::move(unit),
        std::move(path));

    // Adjusting Interface name as per std convention
    capitalize(type);
    capitalize(endpoint);
    auto busName = std::string(busNamePrefix) + '.' + type + '.' + endpoint;
    bus.request_name(busName.c_str());
    event.loop();
    return 0;
}
