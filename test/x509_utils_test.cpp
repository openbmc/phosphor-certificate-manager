#include "config.h"

#include "x509_utils.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <xyz/openbmc_project/Certs/error.hpp>

#include <memory>
#include <stdexcept>

#include <gtest/gtest.h>

namespace phosphor::certs
{
namespace
{
using ::sdbusplus::xyz::openbmc_project::Certs::Error::InvalidCertificate;

using EvpPkeyCtxPtr =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&::EVP_PKEY_CTX_free)>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&::X509_free)>;
using X509StorePtr = std::unique_ptr<X509_STORE, decltype(&::X509_STORE_free)>;

void require(bool condition)
{
    if (!condition)
    {
        throw std::runtime_error("OpenSSL test setup failed");
    }
}

EvpPkeyPtr createKey()
{
    EvpPkeyCtxPtr keyContext(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr),
                             ::EVP_PKEY_CTX_free);
    require(keyContext != nullptr);
    require(EVP_PKEY_keygen_init(keyContext.get()) == 1);
    require(EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext.get(), 2048) == 1);

    EVP_PKEY* rawKey = nullptr;
    require(EVP_PKEY_keygen(keyContext.get(), &rawKey) == 1);
    return EvpPkeyPtr(rawKey, ::EVP_PKEY_free);
}

X509Ptr createCertificate(EVP_PKEY& subjectKey, EVP_PKEY& signingKey,
                          X509_NAME* issuer, const char* commonName,
                          const char* notBefore, const char* notAfter)
{
    X509Ptr certificate(X509_new(), ::X509_free);
    require(certificate != nullptr);
    require(X509_set_version(certificate.get(), 2) == 1);
    require(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) ==
            1);
    require(ASN1_TIME_set_string(X509_getm_notBefore(certificate.get()),
                                 notBefore) == 1);
    require(ASN1_TIME_set_string(X509_getm_notAfter(certificate.get()),
                                 notAfter) == 1);
    require(X509_set_pubkey(certificate.get(), &subjectKey) == 1);

    X509_NAME* subject = X509_get_subject_name(certificate.get());
    require(subject != nullptr);
    require(X509_NAME_add_entry_by_txt(
                subject, "CN", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>(commonName), -1, -1,
                0) == 1);
    require(X509_set_issuer_name(certificate.get(),
                                 issuer == nullptr ? subject : issuer) == 1);
    require(X509_sign(certificate.get(), &signingKey, EVP_sha256()) > 0);

    return certificate;
}

X509StorePtr createStore(X509& certificate)
{
    X509StorePtr store(X509_STORE_new(), ::X509_STORE_free);
    require(store != nullptr);
    require(X509_STORE_add_cert(store.get(), &certificate) == 1);
    return store;
}

TEST(X509UtilsTest, ValidateCertificateStartDateRejectsPreEpochDate)
{
    auto key = createKey();
    auto certificate = createCertificate(*key, *key, nullptr, "pre-epoch",
                                         "19691231235959Z", "20300101000000Z");

    EXPECT_THROW(validateCertificateStartDate(*certificate),
                 InvalidCertificate);
}

TEST(X509UtilsTest, ValidateCertificateAgainstStoreAllowsNotYetValidCertificate)
{
    auto key = createKey();
    auto certificate = createCertificate(*key, *key, nullptr, "future",
                                         "20990101000000Z", "21000101000000Z");
    auto store = createStore(*certificate);

    EXPECT_NO_THROW(validateCertificateAgainstStore(*store, *certificate));
}

TEST(X509UtilsTest, ValidateCertificateAgainstStoreAllowsUntrustedSelfSignedCertificate)
{
    auto key = createKey();
    auto certificate = createCertificate(*key, *key, nullptr, "self-signed",
                                         "20200101000000Z", "20300101000000Z");
    X509StorePtr store(X509_STORE_new(), ::X509_STORE_free);
    ASSERT_NE(store, nullptr);

    EXPECT_NO_THROW(validateCertificateAgainstStore(*store, *certificate));
}

TEST(X509UtilsTest, ValidateCertificateAgainstStoreRejectsInvalidSignature)
{
    auto rootKey = createKey();
    auto leafKey = createKey();
    auto incorrectSigningKey = createKey();
    auto root = createCertificate(*rootKey, *rootKey, nullptr, "root",
                                  "20200101000000Z", "20300101000000Z");
    auto leaf = createCertificate(*leafKey, *incorrectSigningKey,
                                  X509_get_subject_name(root.get()), "leaf",
                                  "20200101000000Z", "20300101000000Z");
    auto store = createStore(*root);

    EXPECT_THROW(validateCertificateAgainstStore(*store, *leaf),
                 InvalidCertificate);
}

TEST(X509UtilsTest,
     ValidateCertificateAgainstStoreMatchesExpiredCertificateConfiguration)
{
    auto key = createKey();
    auto certificate = createCertificate(*key, *key, nullptr, "expired",
                                         "19990101000000Z", "20000101000000Z");
    auto store = createStore(*certificate);

    if constexpr (allowExpired)
    {
        EXPECT_NO_THROW(validateCertificateAgainstStore(*store, *certificate));
    }
    else
    {
        EXPECT_THROW(validateCertificateAgainstStore(*store, *certificate),
                     InvalidCertificate);
    }
}

TEST(X509UtilsTest,
     ValidateCertificateInSSLContextRejectsCertificateWithoutPublicKey)
{
    X509Ptr certificate(X509_new(), ::X509_free);
    ASSERT_NE(certificate, nullptr);

    EXPECT_THROW(validateCertificateInSSLContext(*certificate),
                 InvalidCertificate);
}

} // namespace
} // namespace phosphor::certs