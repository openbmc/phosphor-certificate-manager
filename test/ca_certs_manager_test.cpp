#include "config.h"

#include "bmc-vmi-ca/ca_certs_manager.hpp"

#include <iterator>
#include <sdeventplus/event.hpp>
#include <string>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <gtest/gtest.h>

using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using namespace ca::cert;

class MockCACertMgr : public CACertMgr
{
  public:
    MockCACertMgr(sdbusplus::bus::bus& bus, sdeventplus::Event& event,
                  const char* path) :
        CACertMgr(bus, event, path)
    {
    }

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
    TestCACertMgr() : bus(sdbusplus::bus::new_default())
    {
    }

  protected:
    sdbusplus::bus::bus bus;
};

TEST_F(TestCACertMgr, testObjectCreation)
{
    auto bus = sdbusplus::bus::new_default();
    std::string objPath = "/xyz/openbmc_project/certs/ca";
    auto event = sdeventplus::Event::get_default();
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    MockCACertMgr manager(bus, event, objPath.c_str());

    std::string csrString = "csr string";
    EXPECT_NO_THROW(objPath = manager.createCSRObject(csrString));
    EXPECT_TRUE(manager.getNumOfEntries() == 1);
}

TEST_F(TestCACertMgr, testInvalidArgument)
{
    auto bus = sdbusplus::bus::new_default();
    std::string objPath = "/xyz/openbmc_project/certs/ca";
    auto event = sdeventplus::Event::get_default();
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    MockCACertMgr manager(bus, event, objPath.c_str());

    std::string csrString(4097, 'C');

    EXPECT_THROW(objPath = manager.createCSRObject(csrString), InvalidArgument);
}
TEST_F(TestCACertMgr, DeleteAllCSRObjects)
{
    auto bus = sdbusplus::bus::new_default();
    std::string objPath = "/xyz/openbmc_project/certs/ca";
    auto event = sdeventplus::Event::get_default();

    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    MockCACertMgr manager(bus, event, objPath.c_str());

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
    auto event = sdeventplus::Event::get_default();
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    MockCACertMgr manager(bus, event, objPath.c_str());

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
