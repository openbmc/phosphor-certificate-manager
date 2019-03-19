#include "certs_manager.hpp"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <phosphor-logging/elog-errors.hpp>
#include <xyz/openbmc_project/Certs/Install/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
namespace phosphor
{
namespace certs
{

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

using EVP_PKEY_Ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using X509_REQ_Ptr = std::unique_ptr<X509_REQ, decltype(&::X509_REQ_free)>;
using BIO_Ptr = std::unique_ptr<BIO, decltype(&::BIO_free_all)>;
using BIGNUM_Ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;

/** @brief Constructor to put object onto bus at a dbus path.
 *  @param[in] bus - Bus to attach to.
 *  @param[in] path - Path to attach at.
 *  @param[in] type - Type of the certificate.
 *  @param[in] unit - Unit consumed by this certificate.
 *  @param[in] installPath - Certificate installation path.
 */
Manager::Manager(sdbusplus::bus::bus& bus, const char* path,
                 const CertificateType& type, UnitsToRestart&& unit,
                 CertInstallPath&& installPath) :
    Ifaces(bus, path),
    bus(bus), objectPath(path), certType(type), unitToRestart(std::move(unit)),
    certInstallPath(std::move(installPath))
{
    using InvalidCertificate = sdbusplus::xyz::openbmc_project::Certs::Install::
        Error::InvalidCertificate;
    using Reason =
        xyz::openbmc_project::Certs::Install::InvalidCertificate::REASON;
    if (fs::exists(certInstallPath))
    {
        try
        {
            // TODO: Issue#3 At present supporting only one certificate to be
            // uploaded this need to be revisited to support multiple
            // certificates
            auto certObjectPath = objectPath + '/' + '1';
            certificatePtr = std::make_unique<Certificate>(
                bus, certObjectPath, certType, unitToRestart, certInstallPath,
                certInstallPath);
        }
        catch (const InternalFailure& e)
        {
            report<InternalFailure>();
        }
        catch (const InvalidCertificate& e)
        {
            report<InvalidCertificate>(
                Reason("Existing certificate file is corrupted"));
        }
    }
}

void Manager::install(const std::string filePath)
{
    using NotAllowed =
        sdbusplus::xyz::openbmc_project::Common::Error::NotAllowed;
    using Reason = xyz::openbmc_project::Common::NotAllowed::REASON;
    // TODO: Issue#3 At present supporting only one certificate to be
    // uploaded this need to be revisited to support multiple
    // certificates
    if (certificatePtr != nullptr)
    {
        elog<NotAllowed>(Reason("Certificate already exist"));
    }
    auto certObjectPath = objectPath + '/' + '1';
    certificatePtr =
        std::make_unique<Certificate>(bus, certObjectPath, certType,
                                      unitToRestart, certInstallPath, filePath);
}

void Manager::delete_()
{
    // TODO: #Issue 4 when a certificate is deleted system auto generates
    // certificate file. At present we are not supporting creation of
    // certificate object for the auto-generated certificate file as
    // deletion if only applicable for REST server and Bmcweb does not allow
    // deletion of certificates
    if (certificatePtr != nullptr)
    {
        certificatePtr.reset(nullptr);
    }
}

std::string Manager::generateCSR(
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

    if (!alternativeNames.empty())
    {
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
    }
    if (!challengePassword.empty())
    {
        ret = X509_NAME_add_entry_by_txt(
            x509Name, "challengePassword", MBSTRING_ASC,
            (const unsigned char*)challengePassword.c_str(), -1, -1, 0);
        if (ret != 1)
        {
            log<level::ERR>("Unable to set challengePassword");
            elog<InternalFailure>();
        }
    }
    if (!city.empty())
    {
        ret = X509_NAME_add_entry_by_txt(x509Name, "L", MBSTRING_ASC,
                                         (const unsigned char*)city.c_str(), -1,
                                         -1, 0);
        if (ret != 1)
        {
            log<level::ERR>("Unable to set CITY",
                            entry("CITY=%s", city.c_str()));
            elog<InternalFailure>();
        }
    }
    if (!commonName.empty())
    {
        ret = X509_NAME_add_entry_by_txt(
            x509Name, "CN", MBSTRING_ASC,
            (const unsigned char*)commonName.c_str(), -1, -1, 0);
        if (ret != 1)
        {
            log<level::ERR>("Unable to set commonName",
                            entry("COMMONNAME=%s", commonName.c_str()));
            elog<InternalFailure>();
        }
    }
    if (!contactPerson.empty())
    {
        ret = X509_NAME_add_entry_by_txt(
            x509Name, "name", MBSTRING_ASC,
            (const unsigned char*)contactPerson.c_str(), -1, -1, 0);
        if (ret != 1)
        {
            log<level::ERR>("Unable to set contactPerson",
                            entry("CONTACTPERSON=%s", contactPerson.c_str()));
            elog<InternalFailure>();
        }
    }
    if (!country.empty())
    {
        ret = X509_NAME_add_entry_by_txt(x509Name, "C", MBSTRING_ASC,
                                         (const unsigned char*)country.c_str(),
                                         -1, -1, 0);
        if (ret != 1)
        {
            log<level::ERR>("Unable to set country",
                            entry("COUNTRY=%s", country.c_str()));
            elog<InternalFailure>();
        }
    }
    if (!email.empty())
    {
        ret = X509_NAME_add_entry_by_txt(x509Name, "emailAddress", MBSTRING_ASC,
                                         (const unsigned char*)email.c_str(),
                                         -1, -1, 0);
        if (ret != 1)
        {
            log<level::ERR>("Unable to set email",
                            entry("EMAIL=%s", email.c_str()));
            elog<InternalFailure>();
        }
    }
    if (!givenName.empty())
    {
        ret = X509_NAME_add_entry_by_txt(
            x509Name, "GN", MBSTRING_ASC,
            (const unsigned char*)givenName.c_str(), -1, -1, 0);
        if (ret != 1)
        {
            log<level::ERR>("Unable to set givenName",
                            entry("GIVENNAME=%s", givenName.c_str()));
            elog<InternalFailure>();
        }
    }
    if (!initials.empty())
    {
        ret = X509_NAME_add_entry_by_txt(x509Name, "initials", MBSTRING_ASC,
                                         (const unsigned char*)initials.c_str(),
                                         -1, -1, 0);
        if (ret != 1)
        {
            log<level::ERR>("Unable to set initials",
                            entry("INITIALS=%s", initials.c_str()));
            elog<InternalFailure>();
        }
    }
    if (!keyPairAlgorithm.empty())
    {
        ret = X509_NAME_add_entry_by_txt(
            x509Name, "algorithm", MBSTRING_ASC,
            (const unsigned char*)keyPairAlgorithm.c_str(), -1, -1, 0);
        if (ret != 1)
        {
            log<level::ERR>(
                "Unable to set keyPairAlgorithm",
                entry("KEYPAIRALGORITHM=%s", keyPairAlgorithm.c_str()));
            elog<InternalFailure>();
        }
    }
    if (!keyUsage.empty())
    {
        for (auto& usage : keyUsage)
        {
            ret = X509_NAME_add_entry_by_txt(
                x509Name, "keyUsage", MBSTRING_ASC,
                (const unsigned char*)usage.c_str(), -1, -1, 0);
            if (ret != 1)
            {
                log<level::ERR>("Unable to set keyUsage",
                                entry("KEYUSAGE=%s", usage.c_str()));
                elog<InternalFailure>();
            }
        }
    }
    if (!organization.empty())
    {
        ret = X509_NAME_add_entry_by_txt(
            x509Name, "O", MBSTRING_ASC,
            (const unsigned char*)organization.c_str(), -1, -1, 0);
        if (ret != 1)
        {
            log<level::ERR>("Unable to set organization",
                            entry("ORGANIZATION=%s", organization.c_str()));
            elog<InternalFailure>();
        }
    }
    if (!organizationalUnit.empty())
    {
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
    }
    if (!state.empty())
    {
        ret = X509_NAME_add_entry_by_txt(x509Name, "ST", MBSTRING_ASC,
                                         (const unsigned char*)state.c_str(),
                                         -1, -1, 0);
        if (ret != 1)
        {
            log<level::ERR>("Unable to set state",
                            entry("STATE=%s", state.c_str()));
            elog<InternalFailure>();
        }
    }
    if (!surname.empty())
    {
        ret = X509_NAME_add_entry_by_txt(x509Name, "SN", MBSTRING_ASC,
                                         (const unsigned char*)surname.c_str(),
                                         -1, -1, 0);
        if (ret != 1)
        {
            log<level::ERR>("Unable to set surname",
                            entry("SURNAME=%s", surname.c_str()));
            elog<InternalFailure>();
        }
    }
    if (!unstructuredName.empty())
    {
        ret = X509_NAME_add_entry_by_txt(
            x509Name, "unstructuredName", MBSTRING_ASC,
            (const unsigned char*)unstructuredName.c_str(), -1, -1, 0);
        if (ret != 1)
        {
            log<level::ERR>(
                "Unable to set unstructuredName",
                entry("UNSTRUCTUREDNAME=%s", unstructuredName.c_str()));
            elog<InternalFailure>();
        }
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
    std::string path = fs::path(certInstallPath).parent_path();
    std::string privKeyPath = path + '/' + PRIV_KEY_FILE_NAME;

    FILE* fp = fopen(privKeyPath.c_str(), "w");
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
    // save CSR to file
    std::string csrFilePath = path + '/' + CSR_FILE_NAME;
    ret = saveToFile(csrFilePath, x509Req);
    if (ret <= 0)
    {
        log<level::ERR>("Error occured while saving CSR file");
        elog<InternalFailure>();
        return "";
    }

    return csrFilePath;
}

std::string Manager::cSR()
{
    std::string path = fs::path(certInstallPath).parent_path();
    std::string csrFilePath = path + '/' + CSR_FILE_NAME;
    if (!fs::exists(csrFilePath.c_str()))
    {
        log<level::ERR>("CSR file doesn't exists",
                        entry("FILENAME=%s", csrFilePath.c_str()));
        elog<InternalFailure>();
        return "";
    }
    else
    {
        FILE* fp = std::fopen(csrFilePath.c_str(), "r");
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
}

bool Manager::saveToFile(const std::string& filePath,
                         const X509_REQ_Ptr& x509Req)
{
    if (fs::exists(filePath))
    {
        log<level::INFO>("Removing the existing CSR file",
                         entry("FILENAME=%s", filePath.c_str()));
        if (!fs::remove(filePath.c_str()))
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

    int rc = PEM_write_X509_REQ(fp, x509Req.get());
    if (!rc)
    {
        log<level::ERR>("PEM write routine failed",
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

} // namespace certs
} // namespace phosphor
