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

#include <iostream>
#include <string>
#include<bits/stdc++.h>

#include "argument.hpp"
#include "certs_manager.hpp"
#include "config.h"

static void ExitWithError(const char* err, char** argv)
{
    phosphor::certs::util::ArgumentParser::usage(argv);
    std::cerr << std::endl;
    std::cerr << "ERROR: " << err << std::endl;
    exit(EXIT_FAILURE);
}

inline std::string toLower(std::string s)
{
    //Convert  input string to lower case
    transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

inline std::string capitalize(std::string s)
{
    toLower(s);
    s[0] = std::toupper(s[0]);
    return s;
}

int main(int argc, char** argv)
{
    // Read arguments.
    auto options = phosphor::certs::util::ArgumentParser(argc, argv);

    // Parse arguments
    auto type = std::move((options)["type"]);
    // Change to lower case
    auto lType = toLower(type);
    if ((lType == phosphor::certs::util::ArgumentParser::empty_string) ||
        !((lType == phosphor::certs::SERVER) ||
          (lType == phosphor::certs::CLIENT)))
    {
        ExitWithError("type not specified or invalid.", argv);
    }

    auto endpoint = std::move((options)["endpoint"]);
    if (endpoint == phosphor::certs::util::ArgumentParser::empty_string)
    {
        ExitWithError("endpoint not specified.", argv);
    }

    auto path = std::move((options)["path"]);
    if (path == phosphor::certs::util::ArgumentParser::empty_string)
    {
        ExitWithError("path not specified.", argv);
    }

    // unit is an optional parameter
    auto unit = std::move((options)["unit"]);

    auto bus = sdbusplus::bus::new_default();

    //Adjusting Interface name as per std convention
    auto busName =  std::string(BUSNAME) + '.' +
                    capitalize(lType) + '.' +
                    capitalize(endpoint);

    auto objPath =  std::string(OBJPATH) + '/' +
                    lType + '/' +
                    toLower(endpoint);

    phosphor::certs::Manager manager(bus,
                                     objPath.c_str(),
                                     std::move(lType),
                                     std::move(unit),
                                     std::move(path));
    bus.request_name(busName.c_str());

    while (true)
    {
        // process dbus calls / signals discarding unhandled
        bus.process_discard();
        bus.wait();
    }
    return 0;
}
