#pragma once

#include "xyz/openbmc_project/Certs/Entry/server.hpp"
#include "xyz/openbmc_project/Object/Delete/server.hpp"
#include "xyz/openbmc_project/PLDM/Provider/Certs/Authority/CSR/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>

namespace ca
{
namespace cert
{

namespace internal
{
using EntryInterface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::PLDM::Provider::Certs::Authority::server::
        CSR,
    sdbusplus::xyz::openbmc_project::Certs::server::Entry,
    sdbusplus::xyz::openbmc_project::Object::server::Delete>;
}

class CACertMgr;

/** @class Entry
 *  @brief CA authority certificate Entry implementation.
 *  @details A concrete implementation for the
 *           xyz.openbmc_project.Certs.Entry DBus API
 */
class Entry : public internal::EntryInterface
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
     *  @param[in] csr     - csr string
     *  @param[in] cert    - client certificate
     */
    Entry(sdbusplus::bus_t& bus, const std::string& objPath, uint32_t entryId,
          std::string& csr, std::string& cert, CACertMgr& manager) :
        internal::EntryInterface(bus, objPath.c_str(),
                                 internal::EntryInterface::action::defer_emit),
        bus(bus), id(entryId), manager(manager)

    {
        this->csr(csr);
        clientCertificate(cert);

        // Emit deferred signal.
        this->emit_object_added();
    };

    void delete_() override;

  protected:
    /** @brief sdbusplus handler */
    sdbusplus::bus_t& bus;
    uint32_t id;
    /** @brief object path */
    std::string objectPath;
    /** @brief Reference to Certificate Manager */
    CACertMgr& manager;
};
} // namespace cert
} // namespace ca
