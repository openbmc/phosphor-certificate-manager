#include "config.h"

#include "csr.hpp"

#include <sdbusplus/bus.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <new>
#include <string>
#include <string_view>

#include <gtest/gtest.h>

namespace phosphor::certs
{
namespace
{
namespace fs = std::filesystem;

constexpr auto validCSRContent = R"(-----BEGIN CERTIFICATE REQUEST-----
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

std::string createTempDir()
{
    char dirTemplate[] = "/tmp/CSRTest.XXXXXX";
    auto dirPtr = mkdtemp(dirTemplate);
    if (dirPtr == nullptr)
    {
        throw std::bad_alloc();
    }
    return dirPtr;
}

void writeCSRFile(const std::string& testDir, std::string_view content)
{
    std::ofstream csrFile(fs::path(testDir) / defaultCSRFileName);
    csrFile << content;
}

class TestCSR : public ::testing::Test
{
  public:
    TestCSR() : bus(sdbusplus::bus::new_default()) {}

    void SetUp() override
    {
        testDir = createTempDir();
        certFilePath = testDir + "/certificate.pem";
    }

    void TearDown() override
    {
        fs::remove_all(testDir);
    }

  protected:
    sdbusplus::bus_t bus;
    std::string testDir;
    std::string certFilePath;
};

TEST_F(TestCSR, GetCSRWithSuccessStatus)
{
    writeCSRFile(testDir, validCSRContent);

    std::string objPath = "/xyz/openbmc_project/certs/csr/3";
    CSR csr(bus, objPath.c_str(), std::string(certFilePath), Status::success);

    std::string csrContent = csr.csr();
    EXPECT_FALSE(csrContent.empty());
    EXPECT_NE(csrContent.find("BEGIN CERTIFICATE REQUEST"), std::string::npos);
}

TEST_F(TestCSR, GetCSRWithMissingFile)
{
    std::string objPath = "/xyz/openbmc_project/certs/csr/7";
    CSR csr(bus, objPath.c_str(), std::string(certFilePath), Status::success);

    EXPECT_THROW(
        csr.csr(),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
}

TEST_F(TestCSR, CSRWithInvalidContent)
{
    writeCSRFile(testDir, "This is not a valid CSR content");

    std::string objPath = "/xyz/openbmc_project/certs/csr/15";
    CSR csr(bus, objPath.c_str(), std::string(certFilePath), Status::success);

    EXPECT_THROW(
        csr.csr(),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
}

} // namespace
} // namespace phosphor::certs
