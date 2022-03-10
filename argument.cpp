#include "argument.hpp"

#include "certificate.hpp"

#include <CLI/CLI.hpp>

namespace phosphor::certs
{

void processArguments(int argc, const char* const* argv, Arguments& arguments)
{
    CLI::App app{"OpenBMC Certificate Management Daemon"};
    app.add_option("-t,--type", arguments.typeStr, "certificate type")
        ->required();
    app.add_option("-e,--endpoint", arguments.endpoint, "d-bus endpoint")
        ->required();
    app.add_option("-p,--path", arguments.path, "certificate file path")
        ->required();
    app.add_option("-u,--unit", arguments.unit,
                   "Optional systemd unit need to reload");
    try
    {
        app.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        app.exit(e);
        throw std::invalid_argument("invalid arguments.");
    }
    phosphor::certs::CertificateType type =
        phosphor::certs::stringToCertificateType(arguments.typeStr);
    if (type == phosphor::certs::CertificateType::Unsupported)
    {
        std::cerr << "type not specified or invalid." << std::endl;
        throw std::invalid_argument("type not specified or invalid.");
    }
}
} // namespace phosphor::certs
