#pragma once

#include "com/ibm/VMICertificate/Entry/server.hpp"
#include "xyz/openbmc_project/Object/Delete/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>

namespace ibm
{
namespace vmicert
{

using Delete = sdbusplus::xyz::openbmc_project::Object::server::Delete;
using CSREntry = sdbusplus::com::ibm::VMICertificate::server::Entry;
using CSRIface = sdbusplus::server::object::object<CSREntry, Delete>;

using CSRString = std::string;

class vmiCertMgr;

/** @class Entry
 *  @brief VMI certificate Entry implementation.
 *  @details A concrete implementation for the
 *           com.ibm.VMICertificate.Entry DBus API
 */
class Entry : public CSRIface
{
  public:
    Entry() = delete;
    Entry(const Entry&) = delete;
    Entry& operator=(const Entry&) = delete;
    Entry(Entry&&) = delete;
    Entry& operator=(Entry&&) = delete;
    ~Entry() = default;

    /** @brief Constructor to put object onto bus at a D-Bus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - The D-Bus object path to attach at.
     *  @param[in] entryId - Entry id
     *  @param[in] csrfd   - The unix fd of csr file.
     *  @param[in] certfd  - The unix fd of client certificate file.
     */
    Entry(sdbusplus::bus::bus& bus, const std::string& objPath,
          uint32_t entryId, sdbusplus::message::unix_fd csrFd,
          sdbusplus::message::unix_fd certFd, vmiCertMgr& manager) :
        CSRIface(bus, objPath.c_str(), true),
        bus(bus), id(entryId), manager(manager)
    {
        CSRIface::csrfd(csrFd);
        CSRIface::certfd(certFd);

        // Emit deferred signal.
        this->emit_object_added();
    };

    void delete_() override;

  protected:
    /** @brief sdbusplus handler */
    sdbusplus::bus::bus& bus;
    uint32_t id;
    /** @brief object path */
    std::string objectPath;
    sdbusplus::message::unix_fd csrfd;
    sdbusplus::message::unix_fd certfd;
    /** @brief Reference to Certificate Manager */
    vmiCertMgr& manager;
};
} // namespace vmicert
} // namespace ibm
