#pragma once
#include "certificate.hpp"

#include <openssl/x509.h>

#include <cstring>
#include <experimental/filesystem>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <unordered_map>
#include <xyz/openbmc_project/Certs/Install/error.hpp>
#include <xyz/openbmc_project/Certs/Install/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

namespace phosphor
{
namespace certs
{
// RAII support for openSSL functions.
using X509_Ptr = std::unique_ptr<X509, decltype(&::X509_free)>;

// Supported Types.
static constexpr auto SERVER = "server";
static constexpr auto CLIENT = "client";
static constexpr auto AUTHORITY = "authority";

using Create = sdbusplus::xyz::openbmc_project::Certs::server::Install;
using Delete = sdbusplus::xyz::openbmc_project::Object::server::Delete;
using Ifaces = sdbusplus::server::object::object<Create, Delete>;
using InstallFunc = std::function<void(const std::string&)>;
using InputType = std::string;

using namespace phosphor::logging;
using InvalidCertificate =
    sdbusplus::xyz::openbmc_project::Certs::Install::Error::InvalidCertificate;
using Reason = xyz::openbmc_project::Certs::Install::InvalidCertificate::REASON;

// for placeholders
using namespace std::placeholders;
namespace fs = std::experimental::filesystem;

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
     *  @param[in] certpath - Certificate installation path.
     */
    Manager(sdbusplus::bus::bus& bus, const char* path, const std::string& type,
            std::string&& unit, const std::string& certPath) :
        Ifaces(bus, path),
        bus(bus), path(path), type(type), unit(std::move(unit)),
        certPath(certPath)
    {
        auto installHelper = [this](const auto& filePath) {
            if (!compareKeys(filePath))
            {
                elog<InvalidCertificate>(
                    Reason("Private key does not match the Certificate"));
            };
        };

        typeFuncMap[SERVER] = installHelper;
        typeFuncMap[CLIENT] = installHelper;
        typeFuncMap[AUTHORITY] = [](auto filePath) {};

        // If certificate already exist create an certificate object
        if (fs::exists(certPath))
        {
            X509_Ptr cert = std::move(loadCert(certPath));
            auto certificateString = getCertificateString(cert);
            auto certObjectPath = std::string(path) + '/' + "1";
            certificatePtr = std::make_unique<Certificate>(
                bus, certObjectPath.c_str(), certificateString);
        }
    }

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
    /** @brief systemd unit reload or reset helper function
     *  Reload if the unit supports it and use a restart otherwise.
     *  @param[in] unit - service need to reload.
     */
    virtual void reloadOrReset(const std::string& unit);

    /** @brief helper function to copy the file.
     *  @param[in] src - Source file path to copy
     *  @param[in] dst - Destination path to copy
     */
    void copy(const std::string& src, const std::string& dst);

    /** @brief Certificate verification function
     *        Certificate file specific validation using openssl
     *        verify function also includes expiry date check
     *  @param[in] fileName - Certificate and key full file path.
     *  @return error code from open ssl verify function.
     */
    int32_t verifyCert(const std::string& filePath);

    /** @brief Load Certificate file into the X509 structre.
     *  @param[in] fileName - Certificate and key full file path.
     *  @return pointer to the X509 structure.
     */
    X509_Ptr loadCert(const std::string& filePath);

    /** @brief Public/Private key compare function.
     *         Comparing private key against certificate public key
     *         from input .pem file.
     *  @param[in] fileName - Certificate and key full file path.
     *  @return Return true if Key compare is successful,
     *          false if not
     */
    bool compareKeys(const std::string& filePath);

    std::string getCertificateString(const X509_Ptr& x509_ptr);

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

    /** @brief pointer to certificate */
    std::unique_ptr<Certificate> certificatePtr = nullptr;
};

} // namespace certs
} // namespace phosphor
