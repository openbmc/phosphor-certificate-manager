#include "certs_manager.hpp"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
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
        void SetUp() override
        {
            char temp[] = "/tmp/FakeCerts.XXXXXX";
            certDir = mkdtemp(temp);
            if (certDir.empty())
            {
                throw std::bad_alloc();
            }
        }
        void TearDown() override
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
    EXPECT_NO_THROW({ manager.install("cert.pem"); });
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
    EXPECT_NO_THROW({ manager.install("cert.pem"); });
    EXPECT_EQ(true, fs::exists((certDir + "/cert.pem")));
}

/** @brief Makes sure certificate file is overwritten if one already exist
 */
TEST_F(TestCertsManager, ClientCertAlreadyPresent)
{
    std::string endpoint("LDAP");
    std::string unit("");
    std::string type("Client");
    std::string path(certDir + "/cert.pem");
    auto dstpath = fs::path(path).parent_path();
    fs::create_directories(dstpath);
    fs::copy_file("cert.pem", path, fs::copy_options::overwrite_existing);

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
    EXPECT_NO_THROW({ manager.install("cert.pem"); });
}

class MainApp
{
    public:
        MainApp( phosphor::certs::Manager* manager )
                : manager(manager)
        {
        }
        void install(std::string& path){
            manager->install(path);
        }
        phosphor::certs::Manager* manager;
};

class MockCertManager : public phosphor::certs::Manager{
    public:
        MockCertManager(sdbusplus::bus::bus& bus,
                        const char* path,
                        std::string&& type,
                        std::string&& unit,
                        std::string&& certPath): 
                        Manager(bus, path, std::forward<std::string>(type), 
                            std::forward<std::string>(unit), 
                            std::forward<std::string>(certPath))
        {
        }
        virtual ~MockCertManager()
        {
        }
    
        MOCK_METHOD1(reload, void(const std::string& unit));
        MOCK_METHOD0(clientInstall, void());
        MOCK_METHOD0(serverInstall, void());
};

TEST_F(TestCertsManager, CanDrawSomething) {
    std::string endpoint("https");
    std::string unit("nginx.service");
    std::string type("Server");
    std::string path(certDir + "/cert.pem");
    auto busName =  std::string(BUSNAME) + '.' +
                    capitalize(type) + '.' +
                    capitalize(endpoint);
    auto objPath =  std::string(OBJPATH) + '/' +
                    type + '/' +
                    toLower(endpoint);    
    MockCertManager manager(bus,
                            objPath.c_str(),
                            std::move(type),
                            std::move(unit),
                            std::move(path));
    //EXPECT_CALL(manager, reload("nginx.service")).Times(1);
    EXPECT_CALL(manager, serverInstall()).Times(1);
    
    MainApp mainApp(&manager);
    std::string certpath = "cert.pem";
    EXPECT_NO_THROW({ mainApp.install(certpath); });
}