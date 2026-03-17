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

TEST_F(TestCSR, ConstructorWithSuccessStatus)
{
    std::string objPath = "/xyz/openbmc_project/certs/csr/1";
    EXPECT_NO_THROW(CSR csr(bus, objPath.c_str(), std::string(csrFilePath),
                            Status::success));
}

TEST_F(TestCSR, ConstructorWithFailureStatus)
{
    std::string objPath = "/xyz/openbmc_project/certs/csr/2";
    EXPECT_NO_THROW(CSR csr(bus, objPath.c_str(), std::string(csrFilePath),
                            Status::failure));
}

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

TEST_F(TestCSR, ConstructorWithEmptyPath)
{
    std::string objPath = "/xyz/openbmc_project/certs/csr/6";
    EXPECT_NO_THROW(
        CSR csr(bus, objPath.c_str(), std::string(""), Status::success));
}

TEST_F(TestCSR, ConstructorWithNonExistentFile)
{
    std::string objPath = "/xyz/openbmc_project/certs/csr/7";
    std::string nonExistentPath = testDir + "/nonexistent.csr";
    EXPECT_NO_THROW(CSR csr(bus, objPath.c_str(), std::string(nonExistentPath),
                            Status::success));
}

TEST_F(TestCSR, ConstructorWithLongPath)
{
    std::string objPath = "/xyz/openbmc_project/certs/csr/9";
    std::string longPath(1000, 'a');
    EXPECT_NO_THROW(
        CSR csr(bus, objPath.c_str(), std::string(longPath), Status::success));
}

TEST_F(TestCSR, ConstructorWithSpecialCharactersInPath)
{
    std::string objPath = "/xyz/openbmc_project/certs/csr/10";
    std::string specialPath = testDir + "/test@#$%.csr";
    EXPECT_NO_THROW(CSR csr(bus, objPath.c_str(), std::string(specialPath),
                            Status::success));
}

TEST_F(TestCSR, MultipleCSRObjects)
{
    std::string objPath1 = "/xyz/openbmc_project/certs/csr/11";
    std::string objPath2 = "/xyz/openbmc_project/certs/csr/12";
    std::string objPath3 = "/xyz/openbmc_project/certs/csr/13";

    EXPECT_NO_THROW({
        CSR csr1(bus, objPath1.c_str(), std::string(csrFilePath),
                 Status::success);
        CSR csr2(bus, objPath2.c_str(), std::string(csrFilePath),
                 Status::success);
        CSR csr3(bus, objPath3.c_str(), std::string(csrFilePath),
                 Status::failure);
    });
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

TEST_F(TestCSR, CSRWithLargeFile)
{
    char largeDirTemplate[] = "/tmp/CSRTestLarge.XXXXXX";
    auto largeDirPtr = mkdtemp(largeDirTemplate);
    ASSERT_NE(largeDirPtr, nullptr);
    std::string largeDir = largeDirPtr;

    std::string largeFilePath = largeDir + "/domain.csr";
    std::ofstream largeFile(largeFilePath);
    for (int i = 0; i < 10000; ++i)
    {
        largeFile << std::string(1000, 'A');
    }
    largeFile.close();

    std::string objPath = "/xyz/openbmc_project/certs/csr/16";
    std::string installPath = largeDir + "/large.csr";
    CSR csr(bus, objPath.c_str(), std::string(installPath), Status::success);

    EXPECT_THROW(
        csr.csr(),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);

    fs::remove_all(largeDir);
}

TEST_F(TestCSR, CSRWithBinaryFile)
{
    char binaryDirTemplate[] = "/tmp/CSRTestBinary.XXXXXX";
    auto binaryDirPtr = mkdtemp(binaryDirTemplate);
    ASSERT_NE(binaryDirPtr, nullptr);
    std::string binaryDir = binaryDirPtr;

    std::string binaryFilePath = binaryDir + "/domain.csr";
    std::ofstream binaryFile(binaryFilePath, std::ios::binary);
    for (int i = 0; i < 256; ++i)
    {
        binaryFile << static_cast<char>(i);
    }
    binaryFile.close();

    std::string objPath = "/xyz/openbmc_project/certs/csr/17";
    std::string installPath = binaryDir + "/binary.csr";
    CSR csr(bus, objPath.c_str(), std::string(installPath), Status::success);

    EXPECT_THROW(
        csr.csr(),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);

    fs::remove_all(binaryDir);
}

TEST_F(TestCSR, StatusEnumValues)
{
    EXPECT_NE(static_cast<int>(Status::success),
              static_cast<int>(Status::failure));
}

TEST_F(TestCSR, ConstructorWithDifferentObjectPaths)
{
    std::string objPath1 = "/xyz/openbmc_project/certs/csr/path_test1";
    std::string objPath2 = "/xyz/openbmc_project/certs/csr/path_test2";
    std::string objPath3 = "/xyz/openbmc_project/certs/csr/path_test3";

    EXPECT_NO_THROW({
        CSR csr1(bus, objPath1.c_str(), std::string(csrFilePath),
                 Status::success);
    });

    EXPECT_NO_THROW({
        CSR csr2(bus, objPath2.c_str(), std::string(csrFilePath),
                 Status::success);
    });

    EXPECT_NO_THROW({
        CSR csr3(bus, objPath3.c_str(), std::string(csrFilePath),
                 Status::success);
    });
}

} // namespace
} // namespace phosphor::certs
