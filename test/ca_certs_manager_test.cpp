#include "config.h"

#include "bmc-vmi-ca/ca_certs_manager.hpp"

#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <iterator>
#include <string>

#include <gtest/gtest.h>

namespace ca::cert
{
namespace
{
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;

class MockCACertMgr : public CACertMgr
{
  public:
    MockCACertMgr(sdbusplus::bus_t& bus, const char* path) :
        CACertMgr(bus, path)
    {}

    void deleteAll()
    {
        CACertMgr::deleteAll();
    }

    void erase(uint32_t entryId)
    {
        CACertMgr::erase(entryId);
    }
    std::string createCSRObject(std::string csrString)
    {
        return (signCSR(csrString));
    }

    uint32_t getNumOfEntries()
    {
        return entries.size();
    }

    friend class TestCACertMgr;
};
/**
 * Class to create certificate authority manager unit testcases.
 */
class TestCACertMgr : public ::testing::Test
{
  public:
    TestCACertMgr() : bus(sdbusplus::bus::new_default()) {}

  protected:
    sdbusplus::bus_t bus;
};

TEST_F(TestCACertMgr, testObjectCreation)
{
    auto bus = sdbusplus::bus::new_default();
    std::string objPath = "/xyz/openbmc_project/certs/ca";
    MockCACertMgr manager(bus, objPath.c_str());

    std::string csrString = "csr string";
    EXPECT_NO_THROW(objPath = manager.createCSRObject(csrString));
    EXPECT_TRUE(manager.getNumOfEntries() == 1);
}

TEST_F(TestCACertMgr, testInvalidArgument)
{
    auto bus = sdbusplus::bus::new_default();
    std::string objPath = "/xyz/openbmc_project/certs/ca";
    MockCACertMgr manager(bus, objPath.c_str());

    std::string csrString(4097, 'C');

    EXPECT_THROW(objPath = manager.createCSRObject(csrString), InvalidArgument);
}
TEST_F(TestCACertMgr, DeleteAllCSRObjects)
{
    auto bus = sdbusplus::bus::new_default();
    std::string objPath = "/xyz/openbmc_project/certs/ca";

    MockCACertMgr manager(bus, objPath.c_str());

    std::string csrString = "csr string";

    objPath = manager.createCSRObject(csrString);
    objPath = manager.createCSRObject(csrString);
    EXPECT_TRUE(manager.getNumOfEntries() == 2);
    manager.deleteAll();

    EXPECT_TRUE(manager.getNumOfEntries() == 0);
}
TEST_F(TestCACertMgr, DeleteObjectEntry)
{
    auto bus = sdbusplus::bus::new_default();
    std::string objPath = "/xyz/openbmc_project/certs/ca";
    MockCACertMgr manager(bus, objPath.c_str());

    std::string csrString = "csr string";
    std::string entryPath = manager.createCSRObject(csrString);
    std::size_t pos = entryPath.rfind("/");

    std::string id;
    if (pos != std::string::npos)
    {
        id = entryPath.substr(pos + 1);
    }

    manager.erase(std::stoi(id));
    EXPECT_TRUE(manager.getNumOfEntries() == 0);
}
} // namespace
} // namespace ca::cert
