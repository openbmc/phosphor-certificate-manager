#pragma once
#include "certificate.hpp"

#include <xyz/openbmc_project/Certs/Install/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

namespace phosphor
{
namespace certs
{
using Create = sdbusplus::xyz::openbmc_project::Certs::server::Install;
using Delete = sdbusplus::xyz::openbmc_project::Object::server::Delete;
using Ifaces = sdbusplus::server::object::object<Create, Delete>;

class Manager : public Ifaces
{
  public:
    /* Define all of the basic class operations:
     *     Not allowed:
     *         - Default constructor is not possible due to member
     *           reference
     *         - Move operations due to 'this' being registered as the
     *           'context' with sdbus.
     *     Allowed:
     *         - copy
     *         - Destructor.
     */
    Manager() = delete;
    Manager(const Manager&) = default;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;
    virtual ~Manager() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     *  @param[in] type - Type of the certificate.
     *  @param[in] unit - Unit consumed by this certificate.
     *  @param[in] installPath - Certificate installation path.
     */
    Manager(sdbusplus::bus::bus& bus, const char* path,
            const CertificateType& type, UnitsToRestart&& unit,
            CertInstallPath&& installPath);

    /** @brief Implementation for Install
     *  Replace the existing certificate key file with another
     *  (possibly CA signed) Certificate key file.
     *
     *  @param[in] filePath - Certificate key file path.
     */
    void install(const std::string filePath) override;

    /** @brief Delete the certificate (and possibly revert
     *         to a self-signed certificate).
     */
    void delete_() override;

  private:
    /** @brief sdbusplus handler */
    sdbusplus::bus::bus& bus;

    /** @brief object path */
    std::string objectPath;

    /** @brief Type of the certificate **/
    CertificateType certType;

    /** @brief Unit name associated to the service **/
    UnitsToRestart unitToRestart;

    /** @brief Certificate file installation path **/
    CertInstallPath certInstallPath;

    /** @brief pointer to certificate */
    std::unique_ptr<Certificate> certificatePtr = nullptr;
};

} // namespace certs
} // namespace phosphor
