#include "config.h"

#include "hypervisor_certs_manager.hpp"

#include <filesystem>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/File/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace ibm
{
namespace hypcert
{
static constexpr auto HYP_CERT_PATH =
    "/var/lib/phosphor-certificate-manager/hyp-cert/";
static constexpr auto OBJ_ENTRY = "/com/ibm/HypervisorCertificate/entry";
namespace fs = std::filesystem;
using namespace phosphor::logging;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using Argument = xyz::openbmc_project::Common::InvalidArgument;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

uint32_t HypCertMgr::createHypervisorCSREntry(std::string csr)
{
    fs::path certPath(HYP_CERT_PATH);
    auto id = lastEntryId + 1;
    certPath /= std::to_string(id);
    fs::path csrFile(certPath / "csr");
    fs::path certFile(certPath / "cert");

    if (!fs::exists(certPath))
    {
        fs::create_directories(certPath);
    }

    std::ofstream CSRFile;
    CSRFile.open(csrFile.c_str());
    if (CSRFile.fail())
    {
        auto e = errno;
        log<level::ERR>("Unable to open hypervisor csr File",
                        entry("ERRNO=%d", e),
                        entry("PATH=%s", csrFile.c_str()));
        elog<InternalFailure>();
    }
    CSRFile << csr;
    CSRFile.close();

    FILE* certfp = fopen(certFile.c_str(), "w+");

    if (certfp == nullptr)
    {
        auto e = errno;
        log<level::ERR>("Unable to open hypervisor cert File",
                        entry("ERRNO=%d", e),
                        entry("PATH=%s", certFile.c_str()));
        elog<InternalFailure>();
    }

    FILE* csrfp = fopen(csrFile.c_str(), "r");

    if (csrfp == nullptr)
    {
        auto e = errno;
        log<level::ERR>("Unable to open hypervisor csr File",
                        entry("ERRNO=%d", e),
                        entry("PATH=%s", csrFile.c_str()));
        elog<InternalFailure>();
    }

    try
    {
        auto objPath = fs::path(OBJ_ENTRY) / std::to_string(id);
        entries.insert(std::make_pair(
            id, std::make_unique<Entry>(bus, objPath, id, fileno(csrfp),
                                        fileno(certfp), *this)));
        lastEntryId++;
    }
    catch (const std::invalid_argument& e)
    {
        log<level::ERR>(e.what());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("csr"),
                              Argument::ARGUMENT_VALUE(csr.c_str()));
    }
    return id;
}

void HypCertMgr::erase(uint32_t entryId)
{
    entries.erase(entryId);
    std::error_code ec;
    fs::path certPath(HYP_CERT_PATH);
    certPath /= std::to_string(entryId);

    if (std::filesystem::exists(certPath) &&
        std::filesystem::is_directory(certPath))
    {
        std::filesystem::remove_all(certPath, ec);
        if (ec)
        {
            auto e = errno;
            log<level::ERR>("Unable to delete hypervisor certificate Files",
                            entry("ERRNO=%d", e),
                            entry("PATH=%s", certPath.c_str()));
            elog<InternalFailure>();
        }
    }
}

void HypCertMgr::deleteAll()
{
    auto iter = entries.begin();
    while (iter != entries.end())
    {
        auto& entry = iter->second;
        ++iter;
        entry->delete_();
    }
}

} // namespace hypcert
} // namespace ibm
