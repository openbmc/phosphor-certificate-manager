#include "config.h"

#include "ca_certs_manager.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <filesystem>
#include <fstream>

namespace ca::cert
{
namespace fs = std::filesystem;
using ::phosphor::logging::elog;

using ::sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using Argument =
    ::phosphor::logging::xyz::openbmc_project::Common::InvalidArgument;

static constexpr size_t maxCertSize = 4096;

sdbusplus::message::object_path CACertMgr::signCSR(std::string csr)
{
    std::string objPath;
    try
    {
        if (csr.size() > maxCertSize)
        {
            lg2::error("Invalid CSR size");
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("CSR"),
                                  Argument::ARGUMENT_VALUE(csr.c_str()));
        }
        auto id = lastEntryId + 1;
        objPath = fs::path(objectNamePrefix) / "ca" / "entry" /
                  std::to_string(id);
        std::string cert;
        // Creating the dbus object here with the empty certificate string
        // actual signing is being done by the hypervisor, once it signs then
        // the certificate string would be updated with actual certificate.
        entries.insert(std::make_pair(
            id, std::make_unique<Entry>(bus, objPath, id, csr, cert, *this)));
        lastEntryId++;
    }
    catch (const std::invalid_argument& e)
    {
        lg2::error(e.what());
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("csr"),
                              Argument::ARGUMENT_VALUE(csr.c_str()));
    }
    return objPath;
}

void CACertMgr::erase(uint32_t entryId)
{
    entries.erase(entryId);
}

void CACertMgr::deleteAll()
{
    auto iter = entries.begin();
    while (iter != entries.end())
    {
        auto& entry = iter->second;
        ++iter;
        entry->delete_();
    }
}

} // namespace ca::cert
