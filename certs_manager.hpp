#pragma once
#include <openssl/x509.h>

#include <cstring>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <unordered_map>
#include <xyz/openbmc_project/Certs/Install/server.hpp>

namespace phosphor
{
namespace certs
{
// RAII support for openSSL functions.
using X509_Ptr = std::unique_ptr<X509, decltype(&::X509_free)>;

// Supported Types.
static constexpr auto SERVER = "server";
static constexpr auto CLIENT = "client";

using CreateIface = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::Certs::server::Install>;
using InstallFunc = std::function<void()>;
using InputType = std::string;

class Manager : public CreateIface
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
     *  @param[in] certpath - Certificate installation path.
     */
    Manager(sdbusplus::bus::bus& bus, const char* path, const std::string& type,
            std::string&& unit, std::string&& certPath) :
        CreateIface(bus, path),
        bus(bus), path(path), type(type), unit(std::move(unit)),
        certPath(std::move(certPath))
    {
        typeFuncMap[SERVER] =
            std::bind(&phosphor::certs::Manager::serverInstall, this);
        typeFuncMap[CLIENT] =
            std::bind(&phosphor::certs::Manager::clientInstall, this);
    }

    /** @brief Implementation for Install
     *  Replace the existing certificate key file with another
     *  (possibly CA signed) Certificate key file.
     *
     *  @param[in] path - Certificate key file path.
     */
    void install(const std::string path) override;

  private:
    /** @brief Client certificate Installation helper function **/
    virtual void clientInstall();

    /** @brief Server certificate Installation helper function **/
    virtual void serverInstall();

    /** @brief systemd unit reload helper function
     * @param[in] unit - service need to reload.
     */
    void reload(const std::string& unit);

    /** @brief helper function to copy the file.
     *  @param[in] src - Source file path to copy
     *  @param[in] dst - Destination path to copy
     */
    void copy(const std::string& src, const std::string& dst);

    /** @brief Certificate verification function
     *        Certificate file specific validation using openssl
     *        verify function also includes expiry date check
     *  @param[in] fileName - Certificate and key file name.
     *  @return error code from open ssl verify function.
     */
    uint32_t verifyCert(const std::string& fileName);

    /** @brief Load Certificate file into the X509 structre.
     *  @param[in] fileName - Certificate and key file name.
     *  @return pointer to the X509 structure.
     */
    X509_Ptr loadCert(const std::string& fileName);

    /** @brief Public/Private key compare function.
     *         Comparing private key against certificate public key
     *         from input .pem file.
     *  @param[in] fileName - Certificate and key file name.
     *  @return error code
     *          1 - if the key matches.
     *          0 - if they don't match
     *         -1 - Key types are different
     *         -2 - Operation is not supported
     */
    int32_t compareKeys(const std::string fileName);

    /** @brief sdbusplus handler */
    sdbusplus::bus::bus& bus;

    /** @brief object path */
    std::string path;

    /** @brief Type of the certificate **/
    InputType type;

    /** @brief Unit name associated to the service **/
    std::string unit;

    /** @brief Certificate file installation path **/
    std::string certPath;

    /** @brief Type specific function pointer map **/
    std::unordered_map<InputType, InstallFunc> typeFuncMap;
};

} // namespace certs
} // namespace phosphor
