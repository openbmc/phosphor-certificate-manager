#pragma once
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Certs/CSR/server.hpp>

#include <string>

namespace phosphor::certs
{

enum class Status
{
    success,
    failure,
};

namespace internal
{
using CSRInterface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Certs::server::CSR>;
}

/** @class CSR
 *  @brief To read CSR certificate
 */
class CSR : public internal::CSRInterface
{
  public:
    CSR() = delete;
    ~CSR() = default;
    CSR(const CSR&) = delete;
    CSR& operator=(const CSR&) = delete;
    CSR(CSR&&) = delete;
    CSR& operator=(CSR&&) = delete;

    /** @brief Constructor to put object onto bus at a D-Bus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - The D-Bus object path to attach at.
     *  @param[in] installPath - Certificate installation path.
     *  @param[in] status - Status of Generate CSR request
     */
    CSR(sdbusplus::bus_t& bus, const char* path, std::string&& installPath,
        const Status& status);
    /** @brief Return CSR
     */
    std::string csr() override;

  private:
    /** @brief object path */
    std::string objectPath;

    /** @brief Certificate file installation path **/
    std::string certInstallPath;

    /** @brief Status of GenerateCSR request */
    Status csrStatus;
};
} // namespace phosphor::certs
