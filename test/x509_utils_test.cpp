#include "x509_utils.hpp"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <filesystem>
#include <fstream>
#include <memory>
#include <new>
#include <regex>
#include <string>

#include <gtest/gtest.h>

namespace phosphor::certs
{
namespace
{
namespace fs = std::filesystem;

using ::sdbusplus::xyz::openbmc_project::Certs::Error::InvalidCertificate;
using ::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

using BioPtr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using EvpPkeyCtxPtr =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&::EVP_PKEY_CTX_free)>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&::X509_free)>;

std::string createTempDir()
{
    char directoryTemplate[] = "/tmp/X509UtilsTest.XXXXXX";
    char* directory = mkdtemp(directoryTemplate);
    if (directory == nullptr)
    {
        throw std::bad_alloc();
    }
    return directory;
}

std::string createCertificatePem(long serialNumber, const char* commonName)
{
    EvpPkeyCtxPtr keyContext(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr),
                             ::EVP_PKEY_CTX_free);
    EXPECT_NE(keyContext, nullptr);
    EXPECT_EQ(EVP_PKEY_keygen_init(keyContext.get()), 1);
    EXPECT_EQ(EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext.get(), 2048), 1);

    EVP_PKEY* rawKey = nullptr;
    EXPECT_EQ(EVP_PKEY_keygen(keyContext.get(), &rawKey), 1);
    EvpPkeyPtr key(rawKey, ::EVP_PKEY_free);

    X509Ptr certificate(X509_new(), ::X509_free);
    EXPECT_NE(certificate, nullptr);
    EXPECT_EQ(X509_set_version(certificate.get(), 2), 1);
    EXPECT_EQ(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()),
                               serialNumber),
              1);
    EXPECT_NE(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0),
              nullptr);
    EXPECT_NE(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 86400),
              nullptr);
    EXPECT_EQ(X509_set_pubkey(certificate.get(), key.get()), 1);

    X509_NAME* subject = X509_get_subject_name(certificate.get());
    EXPECT_NE(subject, nullptr);
    EXPECT_EQ(X509_NAME_add_entry_by_txt(
                  subject, "CN", MBSTRING_ASC,
                  reinterpret_cast<const unsigned char*>(commonName), -1, -1,
                  0),
              1);
    EXPECT_EQ(X509_set_issuer_name(certificate.get(), subject), 1);
    EXPECT_GT(X509_sign(certificate.get(), key.get(), EVP_sha256()), 0);

    BioPtr certificateBio(BIO_new(BIO_s_mem()), ::BIO_free);
    EXPECT_NE(certificateBio, nullptr);
    EXPECT_EQ(PEM_write_bio_X509(certificateBio.get(), certificate.get()), 1);

    BUF_MEM* certificateBuffer = nullptr;
    BIO_get_mem_ptr(certificateBio.get(), &certificateBuffer);
    EXPECT_NE(certificateBuffer, nullptr);
    return {certificateBuffer->data, certificateBuffer->length};
}

class X509UtilsTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        temporaryDirectory = createTempDir();
        certificatePath = temporaryDirectory / "certificate.pem";
        bundlePath = temporaryDirectory / "bundle.pem";
        certificatePem = createCertificatePem(1, "x509-utils-one");
        alternateCertificatePem = createCertificatePem(2, "x509-utils-two");
        writeFile(certificatePath, certificatePem);
        writeFile(bundlePath, certificatePem);
    }

    void TearDown() override
    {
        fs::remove_all(temporaryDirectory);
    }

    void writeFile(const fs::path& path, const std::string& content)
    {
        std::ofstream file(path);
        ASSERT_TRUE(file.is_open());
        file << content;
        ASSERT_TRUE(file.good());
    }

    fs::path temporaryDirectory;
    fs::path certificatePath;
    fs::path bundlePath;
    std::string certificatePem;
    std::string alternateCertificatePem;
};

TEST_F(X509UtilsTest, GetX509StoreLoadsValidBundle)
{
    const auto store = getX509Store(bundlePath.string());

    EXPECT_NE(store, nullptr);
}

TEST_F(X509UtilsTest, GetX509StoreRejectsMissingBundle)
{
    EXPECT_THROW(getX509Store((temporaryDirectory / "missing.pem").string()),
                 InvalidCertificate);
}

TEST_F(X509UtilsTest, GetX509StoreRejectsMalformedBundle)
{
    const auto malformedPath = temporaryDirectory / "malformed.pem";
    writeFile(malformedPath, "not a certificate");

    EXPECT_THROW(getX509Store(malformedPath.string()), InvalidCertificate);
}

TEST_F(X509UtilsTest, LoadCertLoadsValidCertificate)
{
    const auto certificate = loadCert(certificatePath.string());

    EXPECT_NE(certificate, nullptr);
}

TEST_F(X509UtilsTest, LoadCertRejectsMissingFile)
{
    EXPECT_THROW(loadCert((temporaryDirectory / "missing.pem").string()),
                 InternalFailure);
}

TEST_F(X509UtilsTest, LoadCertRejectsMalformedFile)
{
    const auto malformedPath = temporaryDirectory / "malformed.pem";
    writeFile(malformedPath, "not a certificate");

    EXPECT_THROW(loadCert(malformedPath.string()), InternalFailure);
}

TEST_F(X509UtilsTest, ParseCertParsesValidPem)
{
    const auto certificate = parseCert(certificatePem);

    EXPECT_NE(certificate, nullptr);
}

TEST_F(X509UtilsTest, ParseCertRejectsEmptyPem)
{
    EXPECT_THROW(parseCert(""), InternalFailure);
}

TEST_F(X509UtilsTest, ParseCertRejectsMalformedPem)
{
    EXPECT_THROW(parseCert("not a certificate"), InternalFailure);
}

TEST_F(X509UtilsTest, GenerateCertIdIsStableHexIdentifier)
{
    const auto certificate = parseCert(certificatePem);

    const std::string firstId = generateCertId(*certificate);
    const std::string secondId = generateCertId(*certificate);

    EXPECT_EQ(firstId, secondId);
    EXPECT_TRUE(std::regex_match(firstId, std::regex("[0-9a-f]{16}")));
}

TEST_F(X509UtilsTest, GenerateCertIdDistinguishesCertificates)
{
    const auto certificate = parseCert(certificatePem);
    const auto alternateCertificate = parseCert(alternateCertificatePem);

    EXPECT_NE(generateCertId(*certificate),
              generateCertId(*alternateCertificate));
}

} // namespace
} // namespace phosphor::certs
