#include "certs_manager.hpp"
#include <gtest/gtest.h>
#include <experimental/filesystem>
#include "xyz/openbmc_project/Common/error.hpp"

namespace fs = std::experimental::filesystem;
static constexpr auto BUSNAME = "xyz.openbmc_project.Certs.Manager";
static constexpr auto OBJPATH = "/xyz/openbmc_project/certs";
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

class TestCertsManager : public ::testing::Test
{
    public:
        TestCertsManager() : bus(sdbusplus::bus::new_default())
        {
        }
        virtual void SetUp()
        {
            char temp[] = "/tmp/FakeCerts.XXXXXX";
            certDir = mkdtemp(temp);
            if (certDir.empty())
            {
                throw std::bad_alloc();
            }
        }
        virtual void TearDown()
        {
            fs::remove_all(certDir);
        }
        std::string toLower(std::string s)
        {
            transform(s.begin(), s.end(), s.begin(), ::tolower);
            return s;
        }
        std::string capitalize(std::string s)
        {
            toLower(s);
            s[0] = std::toupper(s[0]);
            return s;
        }
    protected:
        sdbusplus::bus::bus bus;
        std::string certDir;
};

/** @brief Makes sure client certificate file is copied to the destination
 *  folder
 */
TEST_F(TestCertsManager, ClientCertInstall)
{
    std::string endpoint("LDAP");
    std::string unit("");
    std::string type("Client");
    std::string path(certDir + "/cert.pem");
    auto busName =  std::string(BUSNAME) + '.' +
                    capitalize(type) + '.' +
                    capitalize(endpoint);
    auto objPath =  std::string(OBJPATH) + '/' +
                    type + '/' +
                    toLower(endpoint);
    phosphor::certs::Manager manager(bus,
                                     objPath.c_str(),
                                     std::move(type),
                                     std::move(unit),
                                     std::move(path));
    manager.install("cert.pem");
    EXPECT_EQ(true, fs::exists((certDir + "/cert.pem")));
}

/** @brief Makes sure server certificate file is copied to the destination
 *  folder
 */
TEST_F(TestCertsManager, ServerCertInstall)
{
    std::string endpoint("https");
    std::string unit("");
    std::string type("Server");
    std::string path(certDir + "/cert.pem");
    auto busName =  std::string(BUSNAME) + '.' +
                    capitalize(type) + '.' +
                    capitalize(endpoint);
    auto objPath =  std::string(OBJPATH) + '/' +
                    type + '/' +
                    toLower(endpoint);
    phosphor::certs::Manager manager(bus,
                                     objPath.c_str(),
                                     std::move(type),
                                     std::move(unit),
                                     std::move(path));
    manager.install("cert.pem");
    EXPECT_EQ(true, fs::exists((certDir + "/cert.pem")));
}
