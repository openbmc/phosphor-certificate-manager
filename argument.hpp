#pragma once

#include <string>

namespace phosphor::certs
{

struct Arguments
{
    std::string typeStr;  // certificate type
    std::string endpoint; // d-bus endpoint
    std::string path;     // certificate file path
    std::string unit;     // Optional systemd unit need to reload
};

// Validates all |argv| is valid and set corresponding attributes in
// |arguments|.
int processArguments(int argc, const char* const* argv, Arguments& arguments);
} // namespace phosphor::certs
