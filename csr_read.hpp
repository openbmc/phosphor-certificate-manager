#pragma once
#include <xyz/openbmc_project/Certs/CSR/server.hpp>

namespace phosphor
{
namespace certs
{
using CSR = sdbusplus::xyz::openbmc_project::Certs::server::CSR;
using CSRReadIface = sdbusplus::server::object::object<CSR>;

enum class Status
{
    SUCCESS,
    FAILURE,
};

using CertInstallPath = std::string;
/** @class CSRRead
 *  @brief To read CSR certificate
 */
class CSRRead : public CSRReadIface
{
  public:
    CSRRead() = delete;
    ~CSRRead() = default;
    CSRRead(const CSR&) = delete;
    CSRRead& operator=(const CSRRead&) = delete;
    CSRRead(CSRRead&&) = default;
    CSRRead& operator=(CSRRead&&) = default;

    /** @brief Constructor to put object onto bus at a D-Bus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - The D-Bus object path to attach at.
     *  @param[in] installPath - Certificate installation path.
     *  @param[in] status - Status of Generate CSR request
     */
    CSRRead(sdbusplus::bus::bus& bus, const char* path,
            CertInstallPath&& installPath, const Status& status);
    /** @brief Return CSR
     */
    std::string cSR() override;

  private:
    /** @brief sdbusplus handler */
    sdbusplus::bus::bus& bus;

    /** @brief object path */
    std::string objectPath;

    /** @brief Certificate file installation path **/
    CertInstallPath certInstallPath;

    /** @brief Status of GenerateCSR request */
    Status csrStatus;
};
} // namespace certs
} // namespace phosphor
