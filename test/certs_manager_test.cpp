#include "config.h"

#include "certificate.hpp"
#include "certs_manager.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sdeventplus/event.hpp>
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
        CSRFile = "domain.csr";
        privateKeyFile = "privkey.pem";
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
        fs::remove(CSRFile);
        fs::remove(privateKeyFile);
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
    std::string certificateFile, CSRFile, privateKeyFile;

    std::string certDir;
};

class MainApp
{
  public:
    MainApp(phosphor::certs::Manager* manager,
            phosphor::certs::CSR* csr = nullptr) :
        manager(manager),
        csr(csr)
    {
    }
    void install(std::string& path)
    {
        manager->install(path);
    }

    std::string generateCSR(std::vector<std::string> alternativeNames,
                            std::string challengePassword, std::string city,
                            std::string commonName, std::string contactPerson,
                            std::string country, std::string email,
                            std::string givenName, std::string initials,
                            int64_t keyBitLength, std::string keyCurveId,
                            std::string keyPairAlgorithm,
                            std::vector<std::string> keyUsage,
                            std::string organization,
                            std::string organizationalUnit, std::string state,
                            std::string surname, std::string unstructuredName)
    {
        return (manager->generateCSR(
            alternativeNames, challengePassword, city, commonName,
            contactPerson, country, email, givenName, initials, keyBitLength,
            keyCurveId, keyPairAlgorithm, keyUsage, organization,
            organizationalUnit, state, surname, unstructuredName));
    }
    std::string cSR()
    {
        return (csr->cSR());
    }
    phosphor::certs::Manager* manager;
    phosphor::certs::CSR* csr;
};

/** @brief Check if server install routine is invoked for server setup
 */
TEST_F(TestCertificates, InvokeServerInstall)
{
    std::string endpoint("https");
    std::string unit("");
    std::string type("server");
    std::string installPath(certDir + "/" + certificateFile);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    auto event = sdeventplus::Event::get_default();
    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    Manager manager(bus, event, objPath.c_str(), type, unit, installPath);
    MainApp mainApp(&manager);
    mainApp.install(certificateFile);
    EXPECT_TRUE(fs::exists(installPath));
}

/** @brief Check if client install routine is invoked for client setup
 */
TEST_F(TestCertificates, InvokeClientInstall)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("server");
    std::string installPath(certDir + "/" + certificateFile);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    auto event = sdeventplus::Event::get_default();
    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    Manager manager(bus, event, objPath.c_str(), type, unit, installPath);
    MainApp mainApp(&manager);
    mainApp.install(certificateFile);
    EXPECT_TRUE(fs::exists(installPath));
}

/** @brief Check if authority install routine is invoked for authority setup
 */
TEST_F(TestCertificates, InvokeAuthorityInstall)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("authority");
    std::string installPath(certDir + "/" + certificateFile);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    auto event = sdeventplus::Event::get_default();
    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    Manager manager(bus, event, objPath.c_str(), type, unit, installPath);
    MainApp mainApp(&manager);
    mainApp.install(certificateFile);
    EXPECT_TRUE(fs::exists(installPath));
}

/** @brief Compare the installed certificate with the copied certificate
 */
TEST_F(TestCertificates, CompareInstalledCertificate)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("client");
    std::string installPath(certDir + "/" + certificateFile);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    auto event = sdeventplus::Event::get_default();
    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    Manager manager(bus, event, objPath.c_str(), type, unit, installPath);
    MainApp mainApp(&manager);
    mainApp.install(certificateFile);
    EXPECT_TRUE(fs::exists(installPath));
    EXPECT_TRUE(compareFiles(installPath, certificateFile));
}

/** @brief Check if install fails if certificate file is not found
 */
TEST_F(TestCertificates, TestNoCertificateFile)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("client");
    std::string installPath(certDir + "/" + certificateFile);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    std::string uploadFile = "nofile.pem";
    EXPECT_THROW(
        {
            try
            {
                auto event = sdeventplus::Event::get_default();
                // Attach the bus to sd_event to service user requests
                bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
                Manager manager(bus, event, objPath.c_str(), type, unit,
                                installPath);
                MainApp mainApp(&manager);
                mainApp.install(uploadFile);
            }
            catch (const InternalFailure& e)
            {
                throw;
            }
        },
        InternalFailure);
    EXPECT_FALSE(fs::exists(installPath));
}

/** @brief Test replacing existing certificate
 */
TEST_F(TestCertificates, TestReplaceCertificate)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("server");
    std::string installPath(certDir + "/" + certificateFile);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    auto event = sdeventplus::Event::get_default();
    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    Manager manager(bus, event, objPath.c_str(), type, unit, installPath);
    MainApp mainApp(&manager);
    mainApp.install(certificateFile);
    EXPECT_TRUE(fs::exists(installPath));
    EXPECT_TRUE(fs::exists(installPath));
    CertificatePtr& ptr = manager.getCertificate();
    EXPECT_NE(ptr, nullptr);
    ptr->replace(certificateFile);
    EXPECT_TRUE(fs::exists(installPath));
}

/** @brief Check if install fails if certificate file is empty
 */
TEST_F(TestCertificates, TestEmptyCertificateFile)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("client");
    std::string installPath(certDir + "/" + certificateFile);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    std::string emptyFile("emptycert.pem");
    std::ofstream ofs;
    ofs.open(emptyFile, std::ofstream::out);
    ofs.close();
    EXPECT_THROW(
        {
            try
            {
                auto event = sdeventplus::Event::get_default();
                // Attach the bus to sd_event to service user requests
                bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
                Manager manager(bus, event, objPath.c_str(), type, unit,
                                installPath);
                MainApp mainApp(&manager);
                mainApp.install(emptyFile);
            }
            catch (const InvalidCertificate& e)
            {
                throw;
            }
        },
        InvalidCertificate);
    EXPECT_FALSE(fs::exists(installPath));
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
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    EXPECT_THROW(
        {
            try
            {
                auto event = sdeventplus::Event::get_default();
                // Attach the bus to sd_event to service user requests
                bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
                Manager manager(bus, event, objPath.c_str(), type, unit,
                                installPath);
                MainApp mainApp(&manager);
                mainApp.install(certificateFile);
            }
            catch (const InvalidCertificate& e)
            {
                throw;
            }
        },
        InvalidCertificate);
    EXPECT_FALSE(fs::exists(installPath));
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
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    EXPECT_THROW(
        {
            try
            {
                auto event = sdeventplus::Event::get_default();
                // Attach the bus to sd_event to service user requests
                bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
                Manager manager(bus, event, objPath.c_str(), type, unit,
                                installPath);
                MainApp mainApp(&manager);
                mainApp.install(certificateFile);
            }
            catch (const InternalFailure& e)
            {
                throw;
            }
        },
        InternalFailure);
    EXPECT_FALSE(fs::exists(installPath));
}

/** @brief Check install fails if ceritificate is missing in certificate file
 */
TEST_F(TestInvalidCertificate, TestMissingCeritificate)
{
    std::string endpoint("ldap");
    std::string unit("");
    std::string type("client");
    std::string installPath(certDir + "/" + keyFile);
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    EXPECT_THROW(
        {
            try
            {
                auto event = sdeventplus::Event::get_default();
                // Attach the bus to sd_event to service user requests
                bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
                Manager manager(bus, event, objPath.c_str(), type, unit,
                                installPath);
                MainApp mainApp(&manager);
                mainApp.install(keyFile);
            }
            catch (const InvalidCertificate& e)
            {
                throw;
            }
        },
        InvalidCertificate);
    EXPECT_FALSE(fs::exists(installPath));
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
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    auto event = sdeventplus::Event::get_default();
    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    Manager manager(bus, event, objPath.c_str(), type, unit, installPath);
    MainApp mainApp(&manager);
    mainApp.install(certificateFile);
    EXPECT_TRUE(fs::exists(installPath));
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

TEST_F(TestCertificates, TestGenerateCSR)
{
    std::string endpoint("https");
    std::string unit("");
    std::string type("Server");
    std::string installPath(certDir + "/" + certificateFile);
    std::string CSRPath(certDir + "/" + CSRFile);
    std::string privateKeyPath(certDir + "/" + privateKeyFile);
    std::vector<std::string> alternativeNames{"localhost1", "localhost2"};
    std::string challengePassword("Password");
    std::string city("HYB");
    std::string commonName("abc.com");
    std::string contactPerson("Admin");
    std::string country("IN");
    std::string email("admin@in.ibm.com");
    std::string givenName("givenName");
    std::string initials("G");
    int64_t keyBitLength(2048);
    std::string keyCurveId("0");
    std::string keyPairAlgorithm("RSA");
    std::vector<std::string> keyUsage{"serverAuth", "clientAuth"};
    std::string organization("IBM");
    std::string organizationalUnit("orgUnit");
    std::string state("TS");
    std::string surname("surname");
    std::string unstructuredName("unstructuredName");
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    auto event = sdeventplus::Event::get_default();
    // Attach the bus to sd_event to service user requests
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);
    Manager manager(bus, event, objPath.c_str(), type, unit, installPath);
    Status status;
    CSR csr(bus, objPath.c_str(), CSRPath.c_str(), status);
    MainApp mainApp(&manager, &csr);
    mainApp.generateCSR(alternativeNames, challengePassword, city, commonName,
                        contactPerson, country, email, givenName, initials,
                        keyBitLength, keyCurveId, keyPairAlgorithm, keyUsage,
                        organization, organizationalUnit, state, surname,
                        unstructuredName);
    std::string csrData("");
    // generateCSR takes considerable time to create CSR and privateKey Files
    EXPECT_FALSE(fs::exists(CSRPath));
    EXPECT_FALSE(fs::exists(privateKeyPath));
    EXPECT_THROW(
        {
            try
            {
                csrData = csr.cSR();
            }
            catch (const InternalFailure& e)
            {
                throw;
            }
        },
        InternalFailure);
    // wait for 10 sec to get CSR and privateKey Files generated
    sleep(10);
    EXPECT_TRUE(fs::exists(CSRPath));
    EXPECT_TRUE(fs::exists(privateKeyPath));
    csrData = csr.cSR();
    ASSERT_NE("", csrData.c_str());
}

/** @brief Check default KeyBitLength is used if Key bit length is not given*/
TEST_F(TestCertificates, TestGenerateCSRwithDefaultKeyBitLength)
{
    std::string endpoint("https");
    std::string unit("");
    std::string type("Server");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    std::string CSRPath(certDir + "/" + CSRFile);
    std::string privateKeyPath(certDir + "/" + privateKeyFile);
    std::vector<std::string> alternativeNames{"localhost1", "localhost2"};
    std::string challengePassword("Password");
    std::string city("HYB");
    std::string commonName("abc.com");
    std::string contactPerson("Admin");
    std::string country("IN");
    std::string email("admin@in.ibm.com");
    std::string givenName("givenName");
    std::string initials("G");
    int64_t keyBitLength = 0;
    std::string keyCurveId("0");
    std::string keyPairAlgorithm("RSA");
    std::vector<std::string> keyUsage{"serverAuth", "clientAuth"};
    std::string organization("IBM");
    std::string organizationalUnit("orgUnit");
    std::string state("TS");
    std::string surname("surname");
    std::string unstructuredName("unstructuredName");
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    auto event = sdeventplus::Event::get_default();
    Manager manager(bus, event, objPath.c_str(), type, std::move(unit),
                    std::move(installPath));
    Status status;
    CSR csr(bus, objPath.c_str(), CSRPath.c_str(), status);
    MainApp mainApp(&manager, &csr);
    mainApp.generateCSR(alternativeNames, challengePassword, city, commonName,
                        contactPerson, country, email, givenName, initials,
                        keyBitLength, keyCurveId, keyPairAlgorithm, keyUsage,
                        organization, organizationalUnit, state, surname,
                        unstructuredName);
    std::string csrData("");
    // generateCSR takes considerable time to create CSR and privateKey Files
    EXPECT_FALSE(fs::exists(CSRPath));
    EXPECT_FALSE(fs::exists(privateKeyPath));
    EXPECT_THROW(
        {
            try
            {
                csrData = csr.cSR();
            }
            catch (const InternalFailure& e)
            {
                throw;
            }
        },
        InternalFailure);
    // wait for 10 sec to get CSR and privateKey Files generated
    sleep(10);
    EXPECT_TRUE(fs::exists(CSRPath));
    EXPECT_TRUE(fs::exists(privateKeyPath));
    csrData = csr.cSR();
    ASSERT_NE("", csrData.c_str());
}

/** @brief Check if ECC key pair is generated when user is not given algorithm
 * type. At present RSA and EC key pair algorithm are supported
 */
TEST_F(TestCertificates, TestGenerateCSRwithEmptyKeyPairAlgorithm)
{
    std::string endpoint("https");
    std::string unit("");
    std::string type("Server");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    std::string CSRPath(certDir + "/" + CSRFile);
    std::string privateKeyPath(certDir + "/" + privateKeyFile);
    std::vector<std::string> alternativeNames{"localhost1", "localhost2"};
    std::string challengePassword("Password");
    std::string city("HYB");
    std::string commonName("abc.com");
    std::string contactPerson("Admin");
    std::string country("IN");
    std::string email("admin@in.ibm.com");
    std::string givenName("givenName");
    std::string initials("G");
    int64_t keyBitLength(2048);
    std::string keyCurveId("");
    std::string keyPairAlgorithm("");
    std::vector<std::string> keyUsage{"serverAuth", "clientAuth"};
    std::string organization("IBM");
    std::string organizationalUnit("orgUnit");
    std::string state("TS");
    std::string surname("surname");
    std::string unstructuredName("unstructuredName");
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    auto event = sdeventplus::Event::get_default();
    Manager manager(bus, event, objPath.c_str(), type, std::move(unit),
                    std::move(installPath));
    Status status;
    CSR csr(bus, objPath.c_str(), CSRPath.c_str(), status);
    MainApp mainApp(&manager, &csr);
    mainApp.generateCSR(alternativeNames, challengePassword, city, commonName,
                        contactPerson, country, email, givenName, initials,
                        keyBitLength, keyCurveId, keyPairAlgorithm, keyUsage,
                        organization, organizationalUnit, state, surname,
                        unstructuredName);
    sleep(10);
    EXPECT_TRUE(fs::exists(CSRPath));
    EXPECT_TRUE(fs::exists(privateKeyPath));
}

/** @brief Check if error is thrown when giving un supported key pair
 * algorithm. At present RSA and EC key pair algorithm are supported
 */
TEST_F(TestCertificates, TestGenerateCSRwithUnsupportedKeyPairAlgorithm)
{
    std::string endpoint("https");
    std::string unit("");
    std::string type("Server");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    std::string CSRPath(certDir + "/" + CSRFile);
    std::string privateKeyPath(certDir + "/" + privateKeyFile);
    std::vector<std::string> alternativeNames{"localhost1", "localhost2"};
    std::string challengePassword("Password");
    std::string city("HYB");
    std::string commonName("abc.com");
    std::string contactPerson("Admin");
    std::string country("IN");
    std::string email("admin@in.ibm.com");
    std::string givenName("givenName");
    std::string initials("G");
    int64_t keyBitLength(2048);
    std::string keyCurveId("secp521r1");
    std::string keyPairAlgorithm("UnSupportedAlgorithm");
    std::vector<std::string> keyUsage{"serverAuth", "clientAuth"};
    std::string organization("IBM");
    std::string organizationalUnit("orgUnit");
    std::string state("TS");
    std::string surname("surname");
    std::string unstructuredName("unstructuredName");
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    auto event = sdeventplus::Event::get_default();
    Manager manager(bus, event, objPath.c_str(), type, std::move(unit),
                    std::move(installPath));
    Status status;
    CSR csr(bus, objPath.c_str(), CSRPath.c_str(), status);
    MainApp mainApp(&manager, &csr);
    mainApp.generateCSR(alternativeNames, challengePassword, city, commonName,
                        contactPerson, country, email, givenName, initials,
                        keyBitLength, keyCurveId, keyPairAlgorithm, keyUsage,
                        organization, organizationalUnit, state, surname,
                        unstructuredName);
    EXPECT_FALSE(fs::exists(CSRPath));
    EXPECT_FALSE(fs::exists(privateKeyPath));
}

/** @brief Check if error is thrown when NID_undef is returned for given key
 * curve id
 */
TEST_F(TestCertificates, TestECKeyGenerationwithNIDundefCase)
{
    std::string endpoint("https");
    std::string unit("");
    std::string type("Server");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    std::string CSRPath(certDir + "/" + CSRFile);
    std::string privateKeyPath(certDir + "/" + privateKeyFile);
    std::vector<std::string> alternativeNames{"localhost1", "localhost2"};
    std::string challengePassword("Password");
    std::string city("BLR");
    std::string commonName("abc.com");
    std::string contactPerson("Admin");
    std::string country("IN");
    std::string email("admin@in.ibm.com");
    std::string givenName("givenName");
    std::string initials("G");
    int64_t keyBitLength(2048);
    std::string keyCurveId("DummyCurveName");
    std::string keyPairAlgorithm("EC");
    std::vector<std::string> keyUsage{"serverAuth", "clientAuth"};
    std::string organization("IBM");
    std::string organizationalUnit("orgUnit");
    std::string state("TS");
    std::string surname("surname");
    std::string unstructuredName("unstructuredName");
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    auto event = sdeventplus::Event::get_default();
    Manager manager(bus, event, objPath.c_str(), type, std::move(unit),
                    std::move(installPath));
    Status status;
    CSR csr(bus, objPath.c_str(), CSRPath.c_str(), status);
    MainApp mainApp(&manager, &csr);
    mainApp.generateCSR(alternativeNames, challengePassword, city, commonName,
                        contactPerson, country, email, givenName, initials,
                        keyBitLength, keyCurveId, keyPairAlgorithm, keyUsage,
                        organization, organizationalUnit, state, surname,
                        unstructuredName);
    EXPECT_FALSE(fs::exists(CSRPath));
    EXPECT_FALSE(fs::exists(privateKeyPath));
}

/** @brief Check default Key Curve Id is used if given curve id is empty
 */
TEST_F(TestCertificates, TestECKeyGenerationwithDefaultKeyCurveId)
{
    std::string endpoint("https");
    std::string unit("");
    std::string type("Server");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    std::string CSRPath(certDir + "/" + CSRFile);
    std::string privateKeyPath(certDir + "/" + privateKeyFile);
    std::vector<std::string> alternativeNames{"localhost1", "localhost2"};
    std::string challengePassword("Password");
    std::string city("BLR");
    std::string commonName("abc.com");
    std::string contactPerson("Admin");
    std::string country("IN");
    std::string email("admin@in.ibm.com");
    std::string givenName("givenName");
    std::string initials("G");
    int64_t keyBitLength(2048);
    std::string keyCurveId("");
    std::string keyPairAlgorithm("EC");
    std::vector<std::string> keyUsage{"serverAuth", "clientAuth"};
    std::string organization("IBM");
    std::string organizationalUnit("orgUnit");
    std::string state("TS");
    std::string surname("surname");
    std::string unstructuredName("unstructuredName");
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    auto event = sdeventplus::Event::get_default();
    Manager manager(bus, event, objPath.c_str(), type, std::move(unit),
                    std::move(installPath));
    Status status;
    CSR csr(bus, objPath.c_str(), CSRPath.c_str(), status);
    MainApp mainApp(&manager, &csr);
    mainApp.generateCSR(alternativeNames, challengePassword, city, commonName,
                        contactPerson, country, email, givenName, initials,
                        keyBitLength, keyCurveId, keyPairAlgorithm, keyUsage,
                        organization, organizationalUnit, state, surname,
                        unstructuredName);
    sleep(10);
    EXPECT_TRUE(fs::exists(CSRPath));
    EXPECT_TRUE(fs::exists(privateKeyPath));
}

/** @brief Check if error is not thrown to generate EC key pair
 */
TEST_F(TestCertificates, TestECKeyGeneration)
{
    std::string endpoint("https");
    std::string unit("");
    std::string type("Server");
    std::string installPath(certDir + "/" + certificateFile);
    std::string verifyPath(installPath);
    std::string CSRPath(certDir + "/" + CSRFile);
    std::string privateKeyPath(certDir + "/" + privateKeyFile);
    std::vector<std::string> alternativeNames{"localhost1", "localhost2"};
    std::string challengePassword("Password");
    std::string city("BLR");
    std::string commonName("abc.com");
    std::string contactPerson("Admin");
    std::string country("IN");
    std::string email("admin@in.ibm.com");
    std::string givenName("givenName");
    std::string initials("G");
    int64_t keyBitLength(2048);
    std::string keyCurveId("secp521r1");
    std::string keyPairAlgorithm("EC");
    std::vector<std::string> keyUsage{"serverAuth", "clientAuth"};
    std::string organization("IBM");
    std::string organizationalUnit("orgUnit");
    std::string state("TS");
    std::string surname("surname");
    std::string unstructuredName("unstructuredName");
    auto objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;
    auto event = sdeventplus::Event::get_default();
    Manager manager(bus, event, objPath.c_str(), type, std::move(unit),
                    std::move(installPath));
    Status status;
    CSR csr(bus, objPath.c_str(), CSRPath.c_str(), status);
    MainApp mainApp(&manager, &csr);
    mainApp.generateCSR(alternativeNames, challengePassword, city, commonName,
                        contactPerson, country, email, givenName, initials,
                        keyBitLength, keyCurveId, keyPairAlgorithm, keyUsage,
                        organization, organizationalUnit, state, surname,
                        unstructuredName);
    std::cout << "CSRPath: " << CSRPath << std::endl
              << "privateKeyPath: " << privateKeyPath << std::endl;
    sleep(10);
    EXPECT_TRUE(fs::exists(CSRPath));
    EXPECT_TRUE(fs::exists(privateKeyPath));
}
