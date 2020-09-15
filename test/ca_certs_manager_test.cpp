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

class MainApp
{
  public:
    MainApp(ca::cert::CACertMgr* manager) : manager(manager)
    {
    }
    void deleteAll()
    {
        manager->deleteAll();
    }

    void erase(uint32_t entryId)
    {
        manager->erase(entryId);
    }
    std::string createCSRObject(std::string csrString)
    {
        return (manager->signCSR(csrString));
    }
    ca::cert::CACertMgr* manager;
};

TEST_F(TestCACertMgr, testObjectCreation)
{
    auto bus = sdbusplus::bus::new_default();
    std::string objPath = "/xyz/openbmc_project/certs/ca";
    auto event = sdeventplus::Event::get_default();
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    CACertMgr manager(bus, event, objPath.c_str());
    MainApp mainApp(&manager);

    std::string csrString = "csr string";
    EXPECT_NO_THROW(mainApp.createCSRObject(csrString));
}

TEST_F(TestCACertMgr, testInvalidArgument)
{
    auto bus = sdbusplus::bus::new_default();
    std::string objPath = "/xyz/openbmc_project/certs/ca";
    auto event = sdeventplus::Event::get_default();
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    CACertMgr manager(bus, event, objPath.c_str());
    MainApp mainApp(&manager);

    std::string csrString(4097, 'C');

    EXPECT_THROW(objPath = mainApp.createCSRObject(csrString), InvalidArgument);
    std::cout << objPath << std::endl;
}

TEST_F(TestCACertMgr, DeleteAllCSRObjects)
{
    auto bus = sdbusplus::bus::new_default();
    std::string objPath = "/xyz/openbmc_project/certs/ca";
    auto event = sdeventplus::Event::get_default();

    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    CACertMgr manager(bus, event, objPath.c_str());
    MainApp mainApp(&manager);

    std::string csrString = "csr string";
    mainApp.createCSRObject(csrString);
    mainApp.createCSRObject(csrString);
    std::map<uint32_t, std::unique_ptr<Entry>>& certs = manager.getEntries();
    EXPECT_EQ(certs.size(), 2);

    mainApp.deleteAll();
    EXPECT_EQ(certs.size(), 0);
}

TEST_F(TestCACertMgr, DeleteObjectEntry)
{

    auto bus = sdbusplus::bus::new_default();
    std::string objPath = "/xyz/openbmc_project/certs/ca";
    auto event = sdeventplus::Event::get_default();
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    CACertMgr manager(bus, event, objPath.c_str());
    MainApp mainApp(&manager);

    std::string csrString = "csr string";
    std::string entryPath = mainApp.createCSRObject(csrString);

    std::size_t pos = entryPath.rfind("/");

    std::string id;
    if (pos != std::string::npos)
    {
        id = entryPath.substr(pos + 1);
    }

    mainApp.erase(std::stoi(id));
}
