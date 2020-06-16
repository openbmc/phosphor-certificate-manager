#pragma once

#include "com/ibm/VMICertificate/VMICreateCSREntry/server.hpp"
#include "xyz/openbmc_project/Collection/DeleteAll/server.hpp"
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdeventplus/source/event.hpp>
#include "vmi_cert_entry.hpp"

namespace ibm
{
namespace vmicert
{

class vmiCertMgr;

using CreateIface = sdbusplus::server::object::object<
    sdbusplus::com::ibm::VMICertificate::server::VMICreateCSREntry,
    sdbusplus::xyz::openbmc_project::Collection::server::DeleteAll>;
using Mgr = ibm::vmicert::vmiCertMgr;

/** @class Manager
 *  @brief Implementation for the
 *         com.ibm.VMICertificate DBus API.
 */
class vmiCertMgr : public CreateIface
{
  public:
    vmiCertMgr() = delete;
    vmiCertMgr(const vmiCertMgr&) = delete;
    vmiCertMgr& operator=(const vmiCertMgr&) = delete;
    vmiCertMgr(vmiCertMgr&&) = delete;
    vmiCertMgr& operator=(vmiCertMgr&&) = delete;
    virtual ~vmiCertMgr() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     */
    vmiCertMgr(sdbusplus::bus::bus& bus, sdeventplus::Event& event, const char* path) :
        CreateIface(bus, path), bus(bus),event(event),objectPath(path),lastEntryId(0){};

    /** @brief Implementation for Create
     *  Create VMI entry.
     *  @param[in] csr - csr string 
     */
     uint32_t vMICreateCSREntry(std::string csr) override;

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
    //sdevent Event handle
    sdeventplus::Event& event;

    std::map<uint32_t, std::unique_ptr<Entry>> entries;
    /** @brief object path */
    std::string objectPath;
    /** @brief Id of the last certificate entry */
    uint32_t lastEntryId;
};

} // namespace vmicert
} // namespace ibm
