#include "generate_csr.hpp"

namespace phosphor
{
namespace certs
{

GenerateCSR::GenerateCSR(sdbusplus::bus::bus& bus, const char* path) :
    Ifaces(bus, path, true)
{
}

std::string GenerateCSR::generateCSR(
    std::vector<std::string> alternativeNames, std::string challengePassword,
    std::string city, std::string commonName, std::string contactPerson,
    std::string country, std::string email, std::string givenName,
    std::string initials, int64_t keyBitLength, std::string keyCurveId,
    std::string keyPairAlgorithm, std::vector<std::string> keyUsage,
    std::string organization, std::string organizationalUnit, std::string state,
    std::string surname, std::string unstructuredName)
{
    return "";
}

std::string GenerateCSR::cSR()
{
    return "";
}

} // namespace certs
} // namespace phosphor
