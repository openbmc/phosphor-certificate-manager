#pragma once
#include <unordered_map>
#include <cstring>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Certs/Install/server.hpp>

namespace phosphor
{
namespace certs
{
using CreateIface = sdbusplus::server::object::object <
                    sdbusplus::xyz::openbmc_project::Certs::server::Install >;
using InstallFunc = std::function<void()>;

class Manager : public CreateIface
{
    public:
        /* Define all of the basic class operations:
         *     Not allowed:
         *         - Default constructor to avoid nullptrs.
         *         - Copy operations due to internal unique_ptr.
         *         - Move operations due to 'this' being registered as the
         *           'context' with sdbus.
         *     Allowed:
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
         *  @param[in] certpath - Certificate installation path.
         */
        Manager(sdbusplus::bus::bus& bus,
                const char* path,
                const std::string type,
                const std::string unit,
                const std::string certPath)
            : CreateIface(bus, path),
              bus(bus),
              path(path),
              type(type),
              unit(unit),
              certPath(certPath)
        {
            typeFuncMap["server"] = std::bind(&phosphor::certs::Manager::serverInstall,
                                              this);
            typeFuncMap["client"] = std::bind(&phosphor::certs::Manager::clientInstall,
                                              this);
        }

        /** @brief Implementation for Activate
         *  Replace the existing certificate key file with another
         *  (possibly CA signed) Certificate key file.
         *
         *  @param[in] path - Certificate key file path.
         */
        void install(const std::string path) override;

    private:
        /** @brief Client certificate Installation helper function **/
        void clientInstall();

        /** @brief Server certificate Installation helper function **/
        void serverInstall();

        /** @brief systemd unit reload helper function
          * @param[in] unit - service need to reload.
          */
        inline void reload(const std::string& unit);

        /** @brief helper function copy file.
          *  @param[in] src - Source file path to copy
          *  @param[in] dst - Destination path to copy
          */
        inline void copy(const std::string& src, const std::string& dst);

        /** @brief sdbusplus handler */
        sdbusplus::bus::bus& bus;

        /** @brief object path */
        const std::string& path;

        /** @brief Type of the certificate **/
        const std::string type;

        /** @brief Unit name associated to the service **/
        const std::string unit;

        /** @brief Certificate file installation path **/
        const std::string certPath;

        /** @brief Type specific function pointer map **/
        std::unordered_map<std::string, InstallFunc> typeFuncMap;
};

} // namespace Certs
} // namespace phosphor

