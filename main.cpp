/**
 * Copyright © 2016 IBM Corporation
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
#include <memory>
#include "argument.hpp"
using namespace phosphor::cert;
int main(int argc, char** argv)
{
    auto options = std::make_unique<ArgumentParser>(argc, argv);
    auto dbusPath = (*options)["dbus"];
    auto config = (*options)["config"];
    std::cout << "DBUS path set is " << dbusPath << std::endl;
    std::cout << "config path set is " << config << std::endl;
    while(true)
    {
    }
    return 0;
}
