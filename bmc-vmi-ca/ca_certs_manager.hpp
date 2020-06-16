#pragma once

#include "ca_cert_entry.hpp"
#include "xyz/openbmc_project/Certs/Authority/server.hpp"
#include "xyz/openbmc_project/Collection/DeleteAll/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdeventplus/source/event.hpp>

namespace ca
{
namespace cert
{

class CACertMgr;

using CreateIface = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::Certs::server::Authority,
    sdbusplus::xyz::openbmc_project::Collection::server::DeleteAll>;
using Mgr = ca::cert::CACertMgr;

/** @class Manager
 *  @brief Implementation for the
 *         xyz.openbmc_project.Certs.ca.authority.Manager DBus API.
 */
class CACertMgr : public CreateIface
{
  public:
    CACertMgr() = delete;
    CACertMgr(const CACertMgr&) = delete;
    CACertMgr& operator=(const CACertMgr&) = delete;
    CACertMgr(CACertMgr&&) = delete;
    CACertMgr& operator=(CACertMgr&&) = delete;
    virtual ~CACertMgr() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     */
    CACertMgr(sdbusplus::bus::bus& bus, sdeventplus::Event& event,
              const char* path) :
        CreateIface(bus, path),
        bus(bus), event(event), objectPath(path), lastEntryId(0){};

    /** @brief This method provides signing authority functionality.
     *         Creates ceritficate signing authority request entry.
     *  @param[in] csr - csr string
     *  @return Object path
     */
    sdbusplus::message::object_path signCSR(std::string csr) override;

    /** @brief Erase specified entry d-bus object
     *  @param[in] entryId - unique identifier of the entry
     */
    void erase(uint32_t entryId);

    /** @brief  Erase all entries
     */
    void deleteAll() override;

  private:
    /** @brief sdbusplus DBus bus connection. */
    sdbusplus::bus::bus& bus;
    // sdevent Event handle
    sdeventplus::Event& event;

    std::map<uint32_t, std::unique_ptr<Entry>> entries;
    /** @brief object path */
    std::string objectPath;
    /** @brief Id of the last certificate entry */
    uint32_t lastEntryId;
};

} // namespace cert
} // namespace ca
