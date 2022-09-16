#include "argument.hpp"

#include "certificate.hpp"

#include <CLI/CLI.hpp>

namespace phosphor::certs
{

int processArguments(int argc, const char* const* argv, Arguments& arguments)
{
    CLI::App app{"OpenBMC Certificate Management Daemon"};
    app.add_option("-t,--type", arguments.typeStr, "certificate type")
        ->required();
    app.add_option("-e,--endpoint", arguments.endpoint, "d-bus endpoint")
        ->required();
    app.add_option("-p,--path", arguments.path, "certificate file path")
        ->required();
    app.add_option("-u,--unit", arguments.unit,
                   "Optional systemd unit need to reload")
        ->capture_default_str();
    CLI11_PARSE(app, argc, argv);
    phosphor::certs::CertificateType type =
        phosphor::certs::stringToCertificateType(arguments.typeStr);
    if (type == phosphor::certs::CertificateType::unsupported)
    {
        std::cerr << "type not specified or invalid." << std::endl;
        return 1;
    }
    return 0;
}
} // namespace phosphor::certs
