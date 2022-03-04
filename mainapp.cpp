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

#include "certificate.hpp"
#include "certs_manager.hpp"

#include <systemd/sd-event.h>

#include <CLI/CLI.hpp>
#include <cctype>
#include <cstdlib>
#include <iostream>
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
    CLI::App app{"OpenBMC Certificate Management Daemon"};

    std::string typeStr;
    app.add_option("-t,--type", typeStr, "certificate type")->required();

    std::string endpoint;
    app.add_option("-e,--endpoint", endpoint, "d-bus endpoint")->required();

    std::string path;
    app.add_option("-p,--path", endpoint, "certificate file path")->required();

    // unit is an optional parameter
    std::string unit;
    app.add_option("-u,--unit", unit, "Optional systemd unit need to reload");

    bool dryRun;
    app.add_flag("--dry-run,!--no-dry-run", dryRun,
                 "Don't run event loop and exit immediately")
        ->default_val(false);

    CLI11_PARSE(app, argc, argv);
    phosphor::certs::CertificateType type =
        phosphor::certs::stringToCertificateType(typeStr);
    if (type == phosphor::certs::CertificateType::Unsupported)
    {
        std::cerr << "type not specified or invalid." << std::endl;
        exit(EXIT_FAILURE);
    }

    auto bus = sdbusplus::bus::new_default();
    auto objPath =
        std::string(objectNamePrefix) + '/' + typeStr + '/' + endpoint;

    // Add sdbusplus ObjectManager
    sdbusplus::server::manager::manager objManager(bus, objPath.c_str());

    // Get default event loop
    auto event = sdeventplus::Event::get_default();

    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    phosphor::certs::Manager manager(bus, event, objPath.c_str(), type, unit,
                                     path);

    // Adjusting Interface name as per std convention
    auto busName = std::string(busNamePrefix) + '.' + capitalize(typeStr) +
                   '.' + capitalize(endpoint);
    bus.request_name(busName.c_str());
    if (!dryRun)
    {
        event.loop();
    }
    return 0;
}
