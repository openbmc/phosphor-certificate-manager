#pragma once

#include "config.h"

#include <sdbusplus/bus.hpp>
#include <string>
#include <xyz/openbmc_project/Certs/CSR/Create/server.hpp>
#include <xyz/openbmc_project/Certs/CSR/View/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

namespace phosphor
{
namespace certs
{

using Create = sdbusplus::xyz::openbmc_project::Certs::CSR::server::Create;
using View = sdbusplus::xyz::openbmc_project::Certs::CSR::server::View;
using Ifaces = sdbusplus::server::object::object<Create, View>;

/** @class GenerateCSR
 *  @brief To create, view and dlete CSR certificates
 */
class GenerateCSR : public Ifaces
{
  public:
    GenerateCSR() = delete;
    ~GenerateCSR() = default;
    GenerateCSR(const GenerateCSR&) = delete;
    GenerateCSR& operator=(const GenerateCSR&) = delete;
    GenerateCSR(GenerateCSR&&) = default;
    GenerateCSR& operator=(GenerateCSR&&) = default;

    /** @brief Constructor to put object onto bus at a D-Bus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - The D-Bus object path to attach at.
     */
    GenerateCSR(sdbusplus::bus::bus& bus, const char* path);

    /** @brief Generate Certificate Sigining Request
     */
    std::string generateCSR(
        std::vector<std::string> alternativeNames,
        std::string challengePassword, std::string city, std::string commonName,
        std::string contactPerson, std::string country, std::string email,
        std::string givenName, std::string initials, int64_t keyBitLength,
        std::string keyCurveId, std::string keyPairAlgorithm,
        std::vector<std::string> keyUsage, std::string organization,
        std::string organizationalUnit, std::string state, std::string surname,
        std::string unstructuredName) override;

    /** @brief Return CSR
     */
    std::string cSR() override;
};
} // namespace certs
} // namespace phosphor
