#pragma once

#include "ca_cert_entry.hpp"
#include "xyz/openbmc_project/Certs/Authority/server.hpp"
#include "xyz/openbmc_project/Collection/DeleteAll/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>

namespace ca::cert
{

namespace internal
{
using ManagerInterface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Certs::server::Authority,
    sdbusplus::xyz::openbmc_project::Collection::server::DeleteAll>;
}

class CACertMgr;

/** @class Manager
 *  @brief Implementation for the
 *         xyz.openbmc_project.Certs.ca.authority.Manager DBus API.
 */
class CACertMgr : public internal::ManagerInterface
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
    CACertMgr(sdbusplus::bus_t& bus, const char* path) :
        internal::ManagerInterface(bus, path), bus(bus), objectPath(path),
        lastEntryId(0) {};

    /** @brief This method provides signing authority functionality.
               It signs the certificate and creates the CSR request entry Dbus
     Object.
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

  protected:
    std::map<uint32_t, std::unique_ptr<Entry>> entries;

  private:
    /** @brief sdbusplus DBus bus connection. */
    sdbusplus::bus_t& bus;
    /** @brief object path */
    std::string objectPath;
    /** @brief Id of the last certificate entry */
    uint32_t lastEntryId;
};

} // namespace ca::cert
