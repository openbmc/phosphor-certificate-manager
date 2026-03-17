#include "csr.hpp"

#include <sdbusplus/bus.hpp>

#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

namespace phosphor::certs
{
namespace
{
namespace fs = std::filesystem;

class TestCSR : public ::testing::Test
{
  public:
    TestCSR() : bus(sdbusplus::bus::new_default()) {}

    void SetUp() override
    {
        char dirTemplate[] = "/tmp/CSRTest.XXXXXX";
        auto dirPtr = mkdtemp(dirTemplate);
        if (dirPtr == nullptr)
        {
            throw std::bad_alloc();
        }
        testDir = dirPtr;
        csrFilePath = testDir + "/domain.csr";
        createCSRFile();
    }

    void TearDown() override
    {
        fs::remove_all(testDir);
    }

    void createCSRFile()
    {
        // Valid CSR generated with OpenSSL
        std::string csrContent = R"(-----BEGIN CERTIFICATE REQUEST-----
MIICuzCCAaMCAQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDjAMBgNVBAoMBU15T3JnMRQwEgYDVQQL
DAtFbmdpbmVlcmluZzEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDIe/1YdZab825SdymCORJZQgHZ5c4IbPP/dJ57
4HQriUR2p7avx9AW3Lo4m5TNC8EFju1wQvb5nagm8Kf/MimyOvUVHAX7yFk5MCm3
SJZ20fAJL8Xjnn8s9zodI3DSDV7MrD+TaJ36V5ZcW472Vkj0KL0EMoeZLedXL8tx
NufPGQpaCp2DH5YlvO03T0ElKSWqvSeTj2IZxhDJ2yeuwKhhCnGrkAaRN4k6EE49
DVOhmUgpRn6WokpBlxI7mgRzpdHT14vYPQJE3wYkLbeto4kxI6ASifQBfPC673IB
+TPvEzf3AsWPRJIBzL8RwQzIzw+HJoO+Om7O96/ARIcwd54VAgMBAAGgADANBgkq
hkiG9w0BAQsFAAOCAQEAdBNhx6IvAmrjYGpD6pelJ/v0aR4WUncABsiLk3ZT3EV/
ptx7nuMai+1sR1qGCFhJk+5yBjTRGtwwl7bMsL87Atq9cJgPviDxXdh07bDyFNSz
1N3JtGNIce4/DFxwpvW+rjcAPswG2IUIn5cM/Drjrrih5s+Eu3ROwrw21t63kZtx
9meBJG21l38zZjB5FBVweoAGATAXFtANhGZjjA2xwp4aWlQzOktWZv/mZMBfxX/2
OHpFD9AmMXQKmYl+wbs1NfdnCPPwCotdsznJAQttWJKWYqZqWWWvRRvuWh7TvmB7
K53q6FEWSOqn5lo5PJ2h9XBl5Ge6hadzHeP0pHELjw==
-----END CERTIFICATE REQUEST-----)";

        std::ofstream csrFile(csrFilePath);
        csrFile << csrContent;
        csrFile.close();
    }

  protected:
    sdbusplus::bus_t bus;
    std::string testDir;
    std::string csrFilePath;
};

TEST_F(TestCSR, GetCSRWithSuccessStatus)
{
    std::string objPath = "/xyz/openbmc_project/certs/csr/3";
    CSR csr(bus, objPath.c_str(), std::string(csrFilePath), Status::success);

    std::string csrContent = csr.csr();
    EXPECT_FALSE(csrContent.empty());
    EXPECT_NE(csrContent.find("BEGIN CERTIFICATE REQUEST"), std::string::npos);
}

TEST_F(TestCSR, GetCSRMultipleTimes)
{
    std::string objPath = "/xyz/openbmc_project/certs/csr/5";
    CSR csr(bus, objPath.c_str(), std::string(csrFilePath), Status::success);

    std::string csrContent1 = csr.csr();
    std::string csrContent2 = csr.csr();
    std::string csrContent3 = csr.csr();

    EXPECT_EQ(csrContent1, csrContent2);
    EXPECT_EQ(csrContent2, csrContent3);
}

TEST_F(TestCSR, ConstructorWithNonExistentFile)
{
    std::string objPath = "/xyz/openbmc_project/certs/csr/7";
    std::string nonExistentPath = testDir + "/nonexistent.csr";
    EXPECT_NO_THROW(CSR csr(bus, objPath.c_str(), std::string(nonExistentPath),
                            Status::success));
}

TEST_F(TestCSR, CSRWithEmptyFile)
{
    char emptyDirTemplate[] = "/tmp/CSRTestEmpty.XXXXXX";
    auto emptyDirPtr = mkdtemp(emptyDirTemplate);
    ASSERT_NE(emptyDirPtr, nullptr);
    std::string emptyTestDir = emptyDirPtr;

    std::string emptyFilePath = emptyTestDir + "/domain.csr";
    std::ofstream emptyFile(emptyFilePath);
    emptyFile.close();

    std::string objPath = "/xyz/openbmc_project/certs/csr/14";
    std::string installPath = emptyTestDir + "/empty.csr";
    CSR csr(bus, objPath.c_str(), std::string(installPath), Status::success);

    EXPECT_THROW(
        csr.csr(),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);

    fs::remove_all(emptyTestDir);
}

TEST_F(TestCSR, CSRWithInvalidContent)
{
    char invalidDirTemplate[] = "/tmp/CSRTestInvalid.XXXXXX";
    auto invalidDirPtr = mkdtemp(invalidDirTemplate);
    ASSERT_NE(invalidDirPtr, nullptr);
    std::string invalidDir = invalidDirPtr;

    std::string invalidFilePath = invalidDir + "/domain.csr";
    std::ofstream invalidFile(invalidFilePath);
    invalidFile << "This is not a valid CSR content";
    invalidFile.close();

    std::string objPath = "/xyz/openbmc_project/certs/csr/15";
    std::string installPath = invalidDir + "/invalid.csr";
    CSR csr(bus, objPath.c_str(), std::string(installPath), Status::success);

    EXPECT_THROW(
        csr.csr(),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);

    fs::remove_all(invalidDir);
}

} // namespace
} // namespace phosphor::certs
