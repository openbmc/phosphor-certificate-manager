#pragma once

#include "xyz/openbmc_project/Certs/Certificate/server.hpp"
#include "xyz/openbmc_project/Object/Delete/server.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>


namespace phosphor
{
namespace certs
{
template <typename T>
using ServerObject = typename sdbusplus::server::object::object<T>;

using CertificateIfaces = sdbusplus::server::object::object<
    sdbusplus::xyz::openbmc_project::Certs::server::Certificate>;

class Manager;

/** @class Certificate
 *  @brief OpenBMC Certofocate entry implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Certs.Certificate DBus API
 */
class Certificate : public CertificateIfaces
{
  public:
    Certificate() = delete;
    Certificate(const Certificate&) = delete;
    Certificate& operator=(const Certificate&) = delete;
    Certificate(Certificate&&) = delete;
    Certificate& operator=(Certificate&&) = delete;
    ~Certificate() = default;

    /** @brief Constructor for the Certificate Object
     *  @param[in] bus - Bus to attach to.
     *  @param[in] objPath - Object path to attach to
     *  @param[in] certString - certificate string from certificate file 
     */
    Certificate(sdbusplus::bus::bus& bus, const std::string& objPath, const std::string& certString) :
        CertificateIfaces(bus, objPath.c_str(), true)
    {
        certificateString(certString);
        // Emit deferred signal.
        this->emit_object_added();
    };
};

} // namespace certs
} // namespace phosphor
