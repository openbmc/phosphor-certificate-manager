#include "config.h"

#include "ca_certs_manager.hpp"

#include <filesystem>
#include <fstream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/File/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace ca
{
namespace cert
{
static constexpr auto CA_CERT_PATH =
    "/var/lib/phosphor-certificate-manager/ca-cert/";
static constexpr auto OBJ_ENTRY = "/xyz/openbmc_project/certs/entry";
namespace fs = std::filesystem;
using namespace phosphor::logging;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using Argument = xyz::openbmc_project::Common::InvalidArgument;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

sdbusplus::message::object_path CACertMgr::signCSR(std::string csr)
{
    auto id = lastEntryId + 1;
    std::string objPath;
    std::string cert;
    try
    {
        objPath = fs::path(OBJ_ENTRY) / std::to_string(id);
        entries.insert(std::make_pair(
            id, std::make_unique<Entry>(bus, objPath, id, csr, cert , *this)));
        lastEntryId++;
    }
    catch (const std::invalid_argument& e)
    {
        log<level::ERR>(e.what());
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

} // namespace cert
} // namespace ca
