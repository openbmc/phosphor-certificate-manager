#include "generate_csr.hpp"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <experimental/filesystem>
#include <sdbusplus/bus.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor
{
namespace certs
{

using EVP_PKEY_Ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using X509_REQ_Ptr = std::unique_ptr<X509_REQ, decltype(&::X509_REQ_free)>;
using BIO_Ptr = std::unique_ptr<BIO, decltype(&::BIO_free_all)>;
using BIGNUM_Ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;

namespace fs = std::experimental::filesystem;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

GenerateCSR::GenerateCSR(sdbusplus::bus::bus& bus, const char* path) :
    Ifaces(bus, path, true)
{
}

int GenerateCSR::saveToFile(const std::string& filePath,
                            const X509_REQ_Ptr& x509Req)
{
    int rc = 0;
    if (fs::exists(filePath))
    {
        rc = fs::remove(filePath.c_str());
        if (rc != 0)
        {
            log<level::ERR>("Unable to remove the CSR file",
                            entry("FILENAME=%s", filePath.c_str()));
            elog<InternalFailure>();
            return false;
        }
    }

    FILE* fp = NULL;

    if ((fp = std::fopen(filePath.c_str(), "w")) == NULL)
    {
        log<level::ERR>("Error opening the file to write the CSR",
                        entry("FILENAME=%s", filePath.c_str()));
        elog<InternalFailure>();
        return false;
    }

    /*BIO_Ptr out(BIO_new_file(CSR_FILE, "w"), ::BIO_free_all);
    rc = PEM_write_bio_X509_REQ(out.get(), x509Req.get());*/

    rc = PEM_write_X509_REQ(fp, x509Req.get());
    if (!rc)
    {
        log<level::ERR>("Error writing CSR to file",
                        entry("FILENAME=%s", filePath.c_str()));
        elog<InternalFailure>();
        return false;
    }
    if (fp != NULL)
    {
        fclose(fp);
    }
    return true;
}

std::string GenerateCSR::generateCSR(
    std::vector<std::string> alternativeNames, std::string challengePassword,
    std::string city, std::string commonName, std::string contactPerson,
    std::string country, std::string email, std::string givenName,
    std::string initials, int64_t keyBitLength, std::string keyCurveId,
    std::string keyPairAlgorithm, std::vector<std::string> keyUsage,
    std::string organization, std::string organizationalUnit, std::string state,
    std::string surname, std::string unstructuredName)
{

    // set version of x509 req
    int nVersion = 1;
    X509_REQ_Ptr x509Req(X509_REQ_new(), ::X509_REQ_free);
    int ret = X509_REQ_set_version(x509Req.get(), nVersion);
    if (ret != 1)
    {
        log<level::ERR>("Error occured during X509_REQ_set_version call");
        elog<InternalFailure>();
    }

    // set subject of x509 req
    X509_NAME* x509Name = X509_REQ_get_subject_name(x509Req.get());

    for (auto& name : alternativeNames)
    {
        ret = X509_NAME_add_entry_by_txt(
            x509Name, "subjectAltName", MBSTRING_ASC,
            (const unsigned char*)name.c_str(), -1, -1, 0);
        if (ret != 1)
        {
            log<level::ERR>("Unable to set subjectAltName",
                            entry("NAME=%s", name.c_str()));
            elog<InternalFailure>();
        }
    }
    // challengePassword
    ret = X509_NAME_add_entry_by_txt(
        x509Name, "challengePassword", MBSTRING_ASC,
        (const unsigned char*)challengePassword.c_str(), -1, -1, 0);
    if (ret != 1)
    {
        log<level::ERR>(
            "Unable to set challengePassword",
            entry("CHALLENGEPASSWORD=%s", challengePassword.c_str()));
        elog<InternalFailure>();
    }

    ret = X509_NAME_add_entry_by_txt(x509Name, "L", MBSTRING_ASC,
                                     (const unsigned char*)city.c_str(), -1, -1,
                                     0);
    if (ret != 1)
    {
        log<level::ERR>("Unable to set CITY", entry("CITY=%s", city.c_str()));
        elog<InternalFailure>();
    }
    ret = X509_NAME_add_entry_by_txt(x509Name, "CN", MBSTRING_ASC,
                                     (const unsigned char*)commonName.c_str(),
                                     -1, -1, 0);
    if (ret != 1)
    {
        log<level::ERR>("Unable to set commonName",
                        entry("COMMONNAME=%s", commonName.c_str()));
        elog<InternalFailure>();
    }

    ret = X509_NAME_add_entry_by_txt(
        x509Name, "name", MBSTRING_ASC,
        (const unsigned char*)contactPerson.c_str(), -1, -1, 0);
    if (ret != 1)
    {
        log<level::ERR>("Unable to set contactPerson",
                        entry("CONTACTPERSON=%s", contactPerson.c_str()));
        elog<InternalFailure>();
    }
    ret = X509_NAME_add_entry_by_txt(x509Name, "C", MBSTRING_ASC,
                                     (const unsigned char*)country.c_str(), -1,
                                     -1, 0);
    if (ret != 1)
    {
        log<level::ERR>("Unable to set country",
                        entry("COUNTRY=%s", country.c_str()));
        elog<InternalFailure>();
    }

    ret = X509_NAME_add_entry_by_txt(x509Name, "emailAddress", MBSTRING_ASC,
                                     (const unsigned char*)email.c_str(), -1,
                                     -1, 0);
    if (ret != 1)
    {
        log<level::ERR>("Unable to set email",
                        entry("EMAIL=%s", email.c_str()));
        elog<InternalFailure>();
    }

    ret = X509_NAME_add_entry_by_txt(x509Name, "GN", MBSTRING_ASC,
                                     (const unsigned char*)givenName.c_str(),
                                     -1, -1, 0);
    if (ret != 1)
    {
        log<level::ERR>("Unable to set givenName",
                        entry("GIVENNAME=%s", givenName.c_str()));
        elog<InternalFailure>();
    }
    // "initials" **
    /*ret = X509_NAME_add_entry_by_txt(x509Name, "initials", MBSTRING_ASC,
                                     (const unsigned char*)initials.c_str(), -1,
                                     -1, 0);
    if (ret != 1)
    {
        log<level::ERR>("Unable to set initials", entry("INITIALS=%s",
    initials.c_str())); elog<InternalFailure>();
    }*/

    // keyPairAlgorithm algorithm
    ret = X509_NAME_add_entry_by_txt(
        x509Name, "algorithm", MBSTRING_ASC,
        (const unsigned char*)keyPairAlgorithm.c_str(), -1, -1, 0);
    if (ret != 1)
    {
        log<level::ERR>("Unable to set keyPairAlgorithm",
                        entry("KEYPAIRALGORITHM=%s", keyPairAlgorithm.c_str()));
        elog<InternalFailure>();
    }
    // keyUsage
    for (auto& usage : keyUsage)
    {
        ret = X509_NAME_add_entry_by_txt(x509Name, "keyUsage", MBSTRING_ASC,
                                         (const unsigned char*)usage.c_str(),
                                         -1, -1, 0);
        if (ret != 1)
        {
            log<level::ERR>("Unable to set keyUsage",
                            entry("KEYUSAGE=%s", usage.c_str()));
            elog<InternalFailure>();
        }
    }
    // organizationName
    ret = X509_NAME_add_entry_by_txt(x509Name, "O", MBSTRING_ASC,
                                     (const unsigned char*)organization.c_str(),
                                     -1, -1, 0);
    if (ret != 1)
    {
        log<level::ERR>("Unable to set organization",
                        entry("ORGANIZATION=%s", organization.c_str()));
        elog<InternalFailure>();
    }
    // organizationalUnitName
    ret = X509_NAME_add_entry_by_txt(
        x509Name, "OU", MBSTRING_ASC,
        (const unsigned char*)organizationalUnit.c_str(), -1, -1, 0);
    if (ret != 1)
    {
        log<level::ERR>(
            "Unable to set organizationalUnit",
            entry("ORGANIZATIONUNIT=%s", organizationalUnit.c_str()));
        elog<InternalFailure>();
    }
    ret = X509_NAME_add_entry_by_txt(x509Name, "ST", MBSTRING_ASC,
                                     (const unsigned char*)state.c_str(), -1,
                                     -1, 0);
    if (ret != 1)
    {
        log<level::ERR>("Unable to set state",
                        entry("STATE=%s", state.c_str()));
        elog<InternalFailure>();
    }
    // surname
    ret = X509_NAME_add_entry_by_txt(x509Name, "SN", MBSTRING_ASC,
                                     (const unsigned char*)surname.c_str(), -1,
                                     -1, 0);
    if (ret != 1)
    {
        log<level::ERR>("Unable to set surname",
                        entry("SURNAME=%s", surname.c_str()));
        elog<InternalFailure>();
    }
    // unstructuredName
    ret = X509_NAME_add_entry_by_txt(
        x509Name, "unstructuredName", MBSTRING_ASC,
        (const unsigned char*)unstructuredName.c_str(), -1, -1, 0);
    if (ret != 1)
    {
        log<level::ERR>("Unable to set unstructuredName",
                        entry("UNSTRUCTUREDNAME=%s", unstructuredName.c_str()));
        elog<InternalFailure>();
    }

    // generate rsa key
    BIGNUM_Ptr bne(BN_new(), ::BN_free);
    ret = BN_set_word(bne.get(), RSA_F4);
    if (ret != 1)
    {
        log<level::ERR>("Error occured during BN_set_word call");
        elog<InternalFailure>();
    }

    RSA* r = RSA_new();
    ret = RSA_generate_key_ex(r, keyBitLength, bne.get(), NULL);
    if (ret != 1)
    {
        log<level::ERR>("Error occured during RSA_generate_key_ex call");
        elog<InternalFailure>();
    }

    // set public key of x509 req
    EVP_PKEY_Ptr pKey(EVP_PKEY_new(), ::EVP_PKEY_free);
    EVP_PKEY_assign_RSA(pKey.get(), r);
    r = NULL;

    ret = X509_REQ_set_pubkey(x509Req.get(), pKey.get());
    if (ret != 1)
    {
        log<level::ERR>("Error occured while setting private key");
        elog<InternalFailure>();
    }
    // write private key to file
    FILE* fp = fopen(PRIV_KEY_FILE, "w");
    ret = PEM_write_PrivateKey(fp, pKey.get(), NULL, NULL, 0, 0, NULL);
    if (ret != 1)
    {
        log<level::ERR>("Error occured while storing private key to file");
        elog<InternalFailure>();
    }
    if (fp != NULL)
    {
        std::fclose(fp);
    }

    // set sign key of x509 req
    ret = X509_REQ_sign(x509Req.get(), pKey.get(), EVP_sha256());
    if (ret <= 0)
    {
        log<level::ERR>("Error occured while signing key of x509");
        elog<InternalFailure>();
    }

    ret = saveToFile(CSR_FILE, x509Req);
    if (ret <= 0)
    {
        log<level::ERR>("Error occured while saving CSR file");
        elog<InternalFailure>();
        return "";
    }

    return CSR_FILE;
}

std::string GenerateCSR::cSR()
{
    if (fs::exists(CSR_FILE))
    {
        FILE* fp = std::fopen(CSR_FILE, "r");
        X509_REQ_Ptr x509Req(PEM_read_X509_REQ(fp, NULL, NULL, NULL),
                             ::X509_REQ_free);
        if (fp != NULL)
        {
            std::fclose(fp);
        }

        BIO_Ptr bio(BIO_new(BIO_s_mem()), ::BIO_free_all);
        int ret = PEM_write_bio_X509_REQ(bio.get(), x509Req.get());
        if (ret <= 0)
        {
            log<level::ERR>("Error occured while signing key of x509");
            elog<InternalFailure>();
        }
        BUF_MEM* mem = NULL;
        BIO_get_mem_ptr(bio.get(), &mem);
        std::string pem(mem->data, mem->length);
        return pem;
    }

    return "";
}

} // namespace certs
} // namespace phosphor
