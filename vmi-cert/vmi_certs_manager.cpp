#include "config.h"

#include "vmi_certs_manager.hpp"

#include <filesystem>
#include <fstream>
#include <phosphor-logging/elog.hpp>
#include <xyz/openbmc_project/Common/File/error.hpp>

namespace ibm
{
namespace vmicert
{
static constexpr auto VMI_CERT_PATH =
    "/var/lib/phosphor-certificate-manager/vmi-cert/";
static constexpr auto OBJ_ENTRY = "/com/ibm/VMICertificate/entry";
namespace fs = std::filesystem;
using namespace phosphor::logging;
namespace file_error = sdbusplus::xyz::openbmc_project::Common::File::Error;

uint32_t vmiCertMgr::vMICreateCSREntry(std::string csr)
{
    fs::path certPath(VMI_CERT_PATH);
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
        log<level::ERR>("Unable to open vmi csr File", entry("ERRNO=%d", e),
                        entry("PATH=%s", csrFile.c_str()));
        throw file_error::Open();
    }
    CSRFile << csr;
    CSRFile.close();

    FILE* certfp = fopen(certFile.c_str(), "w+");

    if (certfp == nullptr)
    {
        auto e = errno;
        log<level::ERR>("Unable to open vmi cert File", entry("ERRNO=%d", e),
                        entry("PATH=%s", certFile.c_str()));
        throw file_error::Open();
    }

    FILE* csrfp = fopen(csrFile.c_str(), "r");

    if (csrfp == nullptr)
    {
        auto e = errno;
        log<level::ERR>("Unable to open vmi csr File", entry("ERRNO=%d", e),
                        entry("PATH=%s", csrFile.c_str()));
        throw file_error::Open();
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
    }
    return id;
}

void vmiCertMgr::erase(uint32_t entryId)
{
    entries.erase(entryId);
    std::error_code ec;
    fs::path certPath(VMI_CERT_PATH);
    certPath /= std::to_string(entryId);

    if (std::filesystem::exists(certPath) &&
        std::filesystem::is_directory(certPath))
    {
        std::filesystem::remove_all(certPath, ec);
        if (ec)
        {
            auto e = errno;
            log<level::ERR>("Unable to delete vmi certificate Files",
                            entry("ERRNO=%d", e),
                            entry("PATH=%s", certPath.c_str()));
        }
    }
}

void vmiCertMgr::deleteAll()
{
    auto iter = entries.begin();
    while (iter != entries.end())
    {
        auto& entry = iter->second;
        ++iter;
        entry->delete_();
    }
}
} // namespace vmicert
} // namespace ibm
