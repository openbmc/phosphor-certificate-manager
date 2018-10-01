#include "certs_manager.hpp"
#include <experimental/filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <algorithm>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Certs/Install/error.hpp>

namespace fs = std::experimental::filesystem;
static constexpr auto BUSNAME = "xyz.openbmc_project.Certs.Manager";
static constexpr auto OBJPATH = "/xyz/openbmc_project/certs";
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

using InvalidCertificate =
    sdbusplus::xyz::openbmc_project::Certs::Install::Error::InvalidCertificate;

class TestCertsManager : public ::testing::Test
{
  public:
    TestCertsManager() : bus(sdbusplus::bus::new_default())
    {
    }
    void SetUp() override
    {
        char dirTemplate[] = "/tmp/FakeCerts.XXXXXX";
        auto dirPtr = mkdtemp(dirTemplate);
        if (dirPtr == NULL)
        {
            throw std::bad_alloc();
        }
        certDir = dirPtr;
        certificateFile = "cert.pem";
        std::string cmd = "openssl req -x509 -sha256 -newkey rsa:2048 ";
        cmd += "-keyout cert.pem -out cert.pem -days 3650 ";
        cmd += "-subj "
               "/O=openbmc-project.xyz/CN=localhost"
               " -nodes";
        auto val = std::system(cmd.c_str());
        if (val)
        {
            std::cout << "COMMAND Error: " << val << std::endl;
        }
    }
    void TearDown() override
    {
        fs::remove_all(certDir);
        fs::remove(certificateFile);
    }

    bool compareFiles(const std::string& file1, const std::string& file2)
    {
        std::ifstream f1(file1, std::ifstream::binary | std::ifstream::ate);
        std::ifstream f2(file2, std::ifstream::binary | std::ifstream::ate);

        if (f1.fail() || f2.fail())
        {
            return false; // file problem
        }

        if (f1.tellg() != f2.tellg())
        {
            return false; // size mismatch
        }

        // seek back to beginning and use std::equal to compare contents
        f1.seekg(0, std::ifstream::beg);
        f2.seekg(0, std::ifstream::beg);
        return std::equal(std::istreambuf_iterator<char>(f1.rdbuf()),
                          std::istreambuf_iterator<char>(),
                          std::istreambuf_iterator<char>(f2.rdbuf()));
    }

  protected:
    sdbusplus::bus::bus bus;
    std::string certificateFile;

    std::string certDir;
};

class MainApp
{
  public:
    MainApp(phosphor::certs::Manager* manager) : manager(manager)
    {
    }
    void install(std::string& path)
    {
        manager->install(path);
    }
    phosphor::certs::Manager* manager;
};

class MockCertManager : public phosphor::certs::Manager
{
  public:
    MockCertManager(sdbusplus::bus::bus& bus, const char* path,
                    std::string& type, std::string&& unit,
                    std::string&& certPath) :
        Manager(bus, path, type, std::forward<std::string>(unit),
                std::forward<std::string>(certPath))
    {
    }
    virtual ~MockCertManager()
    {
    }

    MOCK_METHOD0(clientInstall, void());
    MOCK_METHOD0(serverInstall, void());
};

/** @brief Check if server install routine is invoked for server setup
 */
TEST_F(TestCertsManager, InvokeServerInstall)
{
    std::string endpoint("https");
    std::string unit("nginx.service");
    std::string type("server");
    std::string path(certDir + "/" + certificateFile);
    std::string verifyPath(path);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    MockCertManager manager(bus, objPath.c_str(), type, std::move(unit),
                            std::move(path));
    EXPECT_CALL(manager, serverInstall()).Times(1);

    MainApp mainApp(&manager);
    EXPECT_NO_THROW({ mainApp.install(certificateFile); });
    EXPECT_TRUE(fs::exists(verifyPath));
}

/** @brief Check if client install routine is invoked for client setup
 */
TEST_F(TestCertsManager, InvokeClientInstall)
{
    std::string endpoint("ldap");
    std::string unit("nslcd.service");
    std::string type("client");
    std::string path(certDir + "/" + certificateFile);
    std::string verifyPath(path);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    MockCertManager manager(bus, objPath.c_str(), type, std::move(unit),
                            std::move(path));
    EXPECT_CALL(manager, clientInstall()).Times(1);
    MainApp mainApp(&manager);
    EXPECT_NO_THROW({ mainApp.install(certificateFile); });
    EXPECT_TRUE(fs::exists(verifyPath));
}

/** @brief Compare the installed certificate with the copied certificate
 */
TEST_F(TestCertsManager, CompareInstalledCertificate)
{
    std::string endpoint("ldap");
    std::string unit("nslcd.service");
    std::string type("client");
    std::string path(certDir + "/" + certificateFile);
    std::string verifyPath(path);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    MockCertManager manager(bus, objPath.c_str(), type, std::move(unit),
                            std::move(path));
    EXPECT_CALL(manager, clientInstall()).Times(1);
    MainApp mainApp(&manager);
    EXPECT_NO_THROW({ mainApp.install(certificateFile); });
    EXPECT_TRUE(fs::exists(verifyPath));
    EXPECT_TRUE(compareFiles(verifyPath, certificateFile));
}

/** @brief Check if install fails if certificate file is not found
 */
TEST_F(TestCertsManager, TestNoCertificateFile)
{
    std::string endpoint("ldap");
    std::string unit("nslcd.service");
    std::string type("client");
    std::string path(certDir + "/" + certificateFile);
    std::string verifyPath(path);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    MockCertManager manager(bus, objPath.c_str(), type, std::move(unit),
                            std::move(path));
    EXPECT_CALL(manager, clientInstall()).Times(0);
    MainApp mainApp(&manager);
    std::string certpath = "nofile.pem";
    EXPECT_THROW(
        {
            try
            {
                mainApp.install(certpath);
            }
            catch (const InternalFailure& e)
            {
                throw;
            }
        },
        InternalFailure);
    EXPECT_FALSE(fs::exists(verifyPath));
}

/** @brief Check if install fails if certificate file is empty
 */
TEST_F(TestCertsManager, TestEmptyCertificateFile)
{
    std::string endpoint("ldap");
    std::string unit("nslcd.service");
    std::string type("client");

    std::string emptyFile("certcorrupted.pem");
    std::ofstream ofs;
    ofs.open(emptyFile, std::ofstream::out);
    ofs.close();

    std::string path(certDir + "/" + emptyFile);
    std::string verifyPath(path);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    MockCertManager manager(bus, objPath.c_str(), type, std::move(unit),
                            std::move(path));
    EXPECT_CALL(manager, clientInstall()).Times(0);
    MainApp mainApp(&manager);
    EXPECT_THROW(
        {
            try
            {
                mainApp.install(emptyFile);
            }
            catch (const InvalidCertificate& e)
            {
                throw;
            }
        },
        InvalidCertificate);
    EXPECT_FALSE(fs::exists(verifyPath));
    fs::remove(emptyFile);
}

/** @brief Check if install fails for corrupted certificate file
 */
TEST_F(TestCertsManager, TestInvalidCertificateFile)
{
    std::string endpoint("ldap");
    std::string unit("nslcd.service");
    std::string type("client");

    std::string corrputedFile("certcorrupted.pem");
    std::ofstream ofs;
    ofs.open(corrputedFile, std::ofstream::out);
    ofs << " PUBLIC KEY PRIVATE KEY XXXX YYYY ZZZZ";
    ofs.close();

    std::string path(certDir + "/" + corrputedFile);
    std::string verifyPath(path);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    MockCertManager manager(bus, objPath.c_str(), type, std::move(unit),
                            std::move(path));
    EXPECT_CALL(manager, clientInstall()).Times(0);
    MainApp mainApp(&manager);
    EXPECT_THROW(
        {
            try
            {
                mainApp.install(corrputedFile);
            }
            catch (const InvalidCertificate& e)
            {
                throw;
            }
        },
        InvalidCertificate);
    EXPECT_FALSE(fs::exists(verifyPath));
    fs::remove(corrputedFile);
}
