#include "certificate.hpp"
#include "certs_manager.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <gtest/gtest.h>
namespace fs = std::filesystem;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidCertificate =
    sdbusplus::xyz::openbmc_project::Certs::Error::InvalidCertificate;
using namespace phosphor::certs;

/**
 * Class to generate certificate file and test verification of certificate file
 */
class TestCertificates : public ::testing::Test
{
  public:
    TestCertificates() : bus(sdbusplus::bus::new_default())
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
    void delete_()
    {
        manager->delete_();
    }
    phosphor::certs::Manager* manager;
};

/** @brief Check if server install routine is invoked for server setup
 */
TEST_F(TestCertificates, InvokeServerInstall)
{
    std::string endpoint("https");
    std::string unit("");
    std::string type("server");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    UnitsToRestart verifyUnit(unit);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    Certificate certificate(bus, objPath, type, unit, installPath,
                            certificateFile);
    EXPECT_TRUE(fs::exists(verifyPath));
}

/** @brief Check if client install routine is invoked for client setup
 */
TEST_F(TestCertificates, InvokeClientInstall)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("server");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    UnitsToRestart verifyUnit(unit);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    Certificate certificate(bus, objPath, type, unit, installPath,
                            certificateFile);
    EXPECT_TRUE(fs::exists(verifyPath));
}

/** @brief Check if authority install routine is invoked for authority setup
 */
TEST_F(TestCertificates, InvokeAuthorityInstall)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("authority");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    UnitsToRestart verifyUnit(unit);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    Certificate certificate(bus, objPath, type, unit, installPath,
                            certificateFile);
    EXPECT_TRUE(fs::exists(verifyPath));
}

/** @brief Compare the installed certificate with the copied certificate
 */
TEST_F(TestCertificates, CompareInstalledCertificate)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("client");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    UnitsToRestart verifyUnit(unit);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    Certificate certificate(bus, objPath, type, unit, installPath,
                            certificateFile);
    EXPECT_TRUE(fs::exists(verifyPath));
    EXPECT_TRUE(compareFiles(verifyPath, certificateFile));
}

/** @brief Check if install fails if certificate file is not found
 */
TEST_F(TestCertificates, TestNoCertificateFile)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("client");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    std::string verifyUnit(unit);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    std::string uploadFile = "nofile.pem";
    EXPECT_THROW(
        {
            try
            {
                Certificate certificate(bus, objPath, type, unit, installPath,
                                        uploadFile);
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
TEST_F(TestCertificates, TestEmptyCertificateFile)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("client");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    std::string verifyUnit(unit);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    std::string emptyFile("emptycert.pem");
    std::ofstream ofs;
    ofs.open(emptyFile, std::ofstream::out);
    ofs.close();
    EXPECT_THROW(
        {
            try
            {
                Certificate certificate(bus, objPath, type, unit, installPath,
                                        emptyFile);
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

/** @brief Check if install fails if certificate file is corrupted
 */
TEST_F(TestCertificates, TestInvalidCertificateFile)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("client");

    std::ofstream ofs;
    ofs.open(certificateFile, std::ofstream::out);
    ofs << "-----BEGIN CERTIFICATE-----";
    ofs << "ADD_SOME_INVALID_DATA_INTO_FILE";
    ofs << "-----END CERTIFICATE-----";
    ofs.close();

    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    std::string verifyUnit(unit);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    EXPECT_THROW(
        {
            try
            {
                Certificate certificate(bus, objPath, type, unit, installPath,
                                        certificateFile);
            }
            catch (const InvalidCertificate& e)
            {
                throw;
            }
        },
        InvalidCertificate);
    EXPECT_FALSE(fs::exists(verifyPath));
}

/** @brief check certificate delete at manager level
 */
TEST_F(TestCertificates, TestCertManagerDelete)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("client");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    std::string verifyUnit(unit);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    Manager manager(bus, objPath.c_str(), type, std::move(unit),
                    std::move(installPath));
    MainApp mainApp(&manager);
    // delete certificate file and verify file is deleted
    mainApp.delete_();
    EXPECT_FALSE(fs::exists(verifyPath));
}

/** @brief check certificate install at manager level
 */
TEST_F(TestCertificates, TestCertManagerInstall)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("client");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    std::string verifyUnit(unit);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    Manager manager(bus, objPath.c_str(), type, std::move(unit),
                    std::move(installPath));
    MainApp mainApp(&manager);
    mainApp.install(certificateFile);
    EXPECT_TRUE(fs::exists(verifyPath));
}

/**
 * Class to generate private and certificate only file and test verification
 */
class TestInvalidCertificate : public ::testing::Test
{
  public:
    TestInvalidCertificate() : bus(sdbusplus::bus::new_default())
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
        keyFile = "key.pem";
        std::string cmd = "openssl req -x509 -sha256 -newkey rsa:2048 ";
        cmd += "-keyout key.pem -out cert.pem -days 3650 ";
        cmd += "-subj "
               "/O=openbmc-project.xyz/CN=localhost"
               " -nodes";

        auto val = std::system(cmd.c_str());
        if (val)
        {
            std::cout << "command Error: " << val << std::endl;
        }
    }
    void TearDown() override
    {
        fs::remove_all(certDir);
        fs::remove(certificateFile);
        fs::remove(keyFile);
    }

  protected:
    sdbusplus::bus::bus bus;
    std::string certificateFile;
    std::string keyFile;
    std::string certDir;
};

/** @brief Check install fails if private key is missing in certificate file
 */
TEST_F(TestInvalidCertificate, TestMissingPrivateKey)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("client");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    std::string verifyUnit(unit);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    EXPECT_THROW(
        {
            try
            {
                Certificate certificate(bus, objPath, type, unit, installPath,
                                        certificateFile);
            }
            catch (const InvalidCertificate& e)
            {
                throw;
            }
        },
        InvalidCertificate);
    EXPECT_FALSE(fs::exists(verifyPath));
}

/** @brief Check install fails if ceritificate is missing in certificate file
 */
TEST_F(TestInvalidCertificate, TestMissingCeritificate)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("client");
    std::string installPath(certDir + "/" + keyFile);
    std::string verifyPath(installPath);
    std::string verifyUnit(unit);

    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    EXPECT_THROW(
        {
            try
            {
                Certificate certificate(bus, objPath, type, unit, installPath,
                                        keyFile);
            }
            catch (const InvalidCertificate& e)
            {
                throw;
            }
        },
        InvalidCertificate);
    EXPECT_FALSE(fs::exists(verifyPath));
}

/** @brief Check if Manager install method fails for invalid certificate file
 */
TEST_F(TestInvalidCertificate, TestCertManagerInstall)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("client");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    std::string verifyUnit(unit);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    Manager manager(bus, objPath.c_str(), type, std::move(unit),
                    std::move(installPath));
    MainApp mainApp(&manager);
    EXPECT_THROW(
        {
            try
            {
                mainApp.install(certificateFile);
            }
            catch (const InvalidCertificate& e)
            {
                throw;
            }
        },
        InvalidCertificate);
    EXPECT_FALSE(fs::exists(verifyPath));
}

/** @brief Check if error is thrown when multiple certificates are installed
 *  At present only one certificate per service is allowed
 */
TEST_F(TestCertificates, TestCertInstallNotAllowed)
{
    using NotAllowed =
        sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("client");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    std::string verifyUnit(unit);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    Manager manager(bus, objPath.c_str(), type, std::move(unit),
                    std::move(installPath));
    MainApp mainApp(&manager);
    mainApp.install(certificateFile);
    EXPECT_TRUE(fs::exists(verifyPath));
    EXPECT_THROW(
        {
            try
            {
                // install second certificate
                mainApp.install(certificateFile);
            }
            catch (const NotAllowed& e)
            {
                throw;
            }
        },
        NotAllowed);
}
