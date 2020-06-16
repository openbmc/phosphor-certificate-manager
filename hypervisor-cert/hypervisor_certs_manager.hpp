#pragma once

#include "com/ibm/HypervisorCertificate/CreateHypervisorCSREntry/server.hpp"
#include "hypervisor_cert_entry.hpp"
#include "xyz/openbmc_project/Collection/DeleteAll/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdeventplus/source/event.hpp>

namespace ibm
{
namespace hypcert
{

class HypCertMgr;

using CreateIface = sdbusplus::server::object::object<
    sdbusplus::com::ibm::HypervisorCertificate::server::
        CreateHypervisorCSREntry,
    sdbusplus::xyz::openbmc_project::Collection::server::DeleteAll>;
using Mgr = ibm::hypcert::HypCertMgr;

/** @class Manager
 *  @brief Implementation for the
 *         com.ibm.HypervisorCertificate DBus API.
 */
class HypCertMgr : public CreateIface
{
  public:
    HypCertMgr() = delete;
    HypCertMgr(const HypCertMgr&) = delete;
    HypCertMgr& operator=(const HypCertMgr&) = delete;
    HypCertMgr(HypCertMgr&&) = delete;
    HypCertMgr& operator=(HypCertMgr&&) = delete;
    virtual ~HypCertMgr() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     */
    HypCertMgr(sdbusplus::bus::bus& bus, sdeventplus::Event& event,
               const char* path) :
        CreateIface(bus, path),
        bus(bus), event(event), objectPath(path), lastEntryId(0){};

    /** @brief Implementation for Create
     *  Create hypervisor certificate entry.
     *  @param[in] csr - csr string
     */
    uint32_t createHypervisorCSREntry(std::string csr) override;

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

} // namespace hypcert
} // namespace ibm
