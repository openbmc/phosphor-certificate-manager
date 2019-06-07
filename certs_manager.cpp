#include "certs_manager.hpp"

#include <openssl/pem.h>
#include <unistd.h>

#include <phosphor-logging/elog-errors.hpp>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
namespace phosphor
{
namespace certs
{
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

using X509_REQ_Ptr = std::unique_ptr<X509_REQ, decltype(&::X509_REQ_free)>;
using BIGNUM_Ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;

Manager::Manager(sdbusplus::bus::bus& bus, sdeventplus::Event& event,
                 const char* path, const CertificateType& type,
                 UnitsToRestart&& unit, CertInstallPath&& installPath) :
    Ifaces(bus, path),
    bus(bus), event(event), objectPath(path), certType(type),
    unitToRestart(std::move(unit)), certInstallPath(std::move(installPath)),
    childPtr(nullptr)
{
    using InvalidCertificate =
        sdbusplus::xyz::openbmc_project::Certs::Error::InvalidCertificate;
    using Reason = xyz::openbmc_project::Certs::InvalidCertificate::REASON;
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
                certInstallPath, true);
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
    certificatePtr = std::make_unique<Certificate>(
        bus, certObjectPath, certType, unitToRestart, certInstallPath, filePath,
        false);
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
    // We support only one CSR.
    csrPtr.reset(nullptr);
    auto pid = fork();
    if (pid == -1)
    {
        log<level::ERR>("Error occurred during forking process");
        report<InternalFailure>();
    }
    else if (pid == 0)
    {
        try
        {
            generateCSRHelper(alternativeNames, challengePassword, city,
                              commonName, contactPerson, country, email,
                              givenName, initials, keyBitLength, keyCurveId,
                              keyPairAlgorithm, keyUsage, organization,
                              organizationalUnit, state, surname,
                              unstructuredName);
            exit(EXIT_SUCCESS);
        }
        catch (const InternalFailure& e)
        {
            // commit the error reported in child process and exit
            // Callback method from SDEvent Loop looks for exit status
            exit(EXIT_FAILURE);
            commit<InternalFailure>();
        }
    }
    else
    {
        using namespace sdeventplus::source;
        Child::Callback callback = [this](Child& eventSource,
                                          const siginfo_t* si) {
            eventSource.set_enabled(Enabled::On);
            if (si->si_status != 0)
            {
                this->createCSRObject(Status::FAILURE);
            }
            else
            {
                this->createCSRObject(Status::SUCCESS);
            }
        };
        try
        {
            sigset_t ss;
            if (sigemptyset(&ss) < 0)
            {
                log<level::ERR>("Unable to initialize signal set");
                elog<InternalFailure>();
            }
            if (sigaddset(&ss, SIGCHLD) < 0)
            {
                log<level::ERR>("Unable to add signal to signal set");
                elog<InternalFailure>();
            }

            // Block SIGCHLD first, so that the event loop can handle it
            if (sigprocmask(SIG_BLOCK, &ss, NULL) < 0)
            {
                log<level::ERR>("Unable to block signal");
                elog<InternalFailure>();
            }
            if (childPtr)
            {
                childPtr.reset();
            }
            childPtr = std::make_unique<Child>(event, pid, WEXITED | WSTOPPED,
                                               std::move(callback));
        }
        catch (const InternalFailure& e)
        {
            commit<InternalFailure>();
        }
    }
    auto csrObjectPath = objectPath + '/' + "csr";
    return csrObjectPath;
}

void Manager::generateCSRHelper(
    std::vector<std::string> alternativeNames, std::string challengePassword,
    std::string city, std::string commonName, std::string contactPerson,
    std::string country, std::string email, std::string givenName,
    std::string initials, int64_t keyBitLength, std::string keyCurveId,
    std::string keyPairAlgorithm, std::vector<std::string> keyUsage,
    std::string organization, std::string organizationalUnit, std::string state,
    std::string surname, std::string unstructuredName)
{
    int ret = 0;

    // set version of x509 req
    int nVersion = 1;
    // TODO: Issue#6 need to make version number configurable
    X509_REQ_Ptr x509Req(X509_REQ_new(), ::X509_REQ_free);
    ret = X509_REQ_set_version(x509Req.get(), nVersion);
    if (ret == 0)
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
            addEntry(x509Name, "subjectAltName", name);
        }
    }
    addEntry(x509Name, "challengePassword", challengePassword);
    addEntry(x509Name, "L", city);
    addEntry(x509Name, "CN", commonName);
    addEntry(x509Name, "name", contactPerson);
    addEntry(x509Name, "C", country);
    addEntry(x509Name, "emailAddress", email);
    addEntry(x509Name, "GN", givenName);
    addEntry(x509Name, "initials", initials);
    addEntry(x509Name, "algorithm", keyPairAlgorithm);
    if (!keyUsage.empty())
    {
        for (auto& usage : keyUsage)
        {
            addEntry(x509Name, "keyUsage", usage);
        }
    }
    addEntry(x509Name, "O", organization);
    addEntry(x509Name, "ST", state);
    addEntry(x509Name, "SN", surname);
    addEntry(x509Name, "unstructuredName", unstructuredName);

    EVP_PKEY_Ptr pKey(nullptr, ::EVP_PKEY_free);

    log<level::INFO>("Given Key pair algorithm",
                     entry("KEYPAIRALGORITHM=%s", keyPairAlgorithm.c_str()));

    /** * Used EC algorithm as default if user did not give algorithm type.
     *   * Error is not require to throw if given algorithm is other than RSA
     * and EC, because bmcweb handled this case. So, this case won't occur here.
     */
    if (keyPairAlgorithm == "RSA")
        pKey = std::move(generateRSAKeyPair(keyBitLength));
    else if ((keyPairAlgorithm == "EC") || (keyPairAlgorithm.empty()))
        pKey = std::move(generateECKeyPair(keyCurveId));

    ret = X509_REQ_set_pubkey(x509Req.get(), pKey.get());
    if (ret == 0)
    {
        log<level::ERR>("Error occured while setting Public key");
        elog<InternalFailure>();
    }

    // Write private key to file
    writePrivateKey(pKey);

    // set sign key of x509 req
    ret = X509_REQ_sign(x509Req.get(), pKey.get(), EVP_sha256());
    if (ret == 0)
    {
        log<level::ERR>("Error occured while signing key of x509");
        elog<InternalFailure>();
    }

    log<level::INFO>("Writing CSR to file");
    std::string path = fs::path(certInstallPath).parent_path();
    std::string csrFilePath = path + '/' + CSR_FILE_NAME;
    writeCSR(csrFilePath, x509Req);
}

EVP_PKEY_Ptr Manager::generateRSAKeyPair(int64_t keyBitLength)
{
    int ret = 0;
    // generate rsa key
    BIGNUM_Ptr bne(BN_new(), ::BN_free);
    ret = BN_set_word(bne.get(), RSA_F4);
    if (ret == 0)
    {
        log<level::ERR>("Error occured during BN_set_word call");
        elog<InternalFailure>();
    }

    // set keybit length to default value if not set
    if (keyBitLength <= 0)
    {
        log<level::WARNING>(
            "KeyBitLength is not given.Hence, using default KeyBitLength",
            entry("DEFAULTKEYBITLENGTH=%d", DEFAULT_KEYBITLENGTH));
        keyBitLength = DEFAULT_KEYBITLENGTH;
    }
    RSA* rsa = RSA_new();
    ret = RSA_generate_key_ex(rsa, keyBitLength, bne.get(), NULL);
    if (ret != 1)
    {
        free(rsa);
        log<level::ERR>("Error occured during RSA_generate_key_ex call",
                        entry("KEYBITLENGTH=%PRIu64", keyBitLength));
        elog<InternalFailure>();
    }

    // set public key of x509 req
    EVP_PKEY_Ptr pKey(EVP_PKEY_new(), ::EVP_PKEY_free);
    ret = EVP_PKEY_assign_RSA(pKey.get(), rsa);
    if (ret == 0)
    {
        free(rsa);
        log<level::ERR>("Error occured during assign rsa key into EVP");
        elog<InternalFailure>();
    }

    return pKey;
}

EVP_PKEY_Ptr Manager::generateECKeyPair(std::string& p_KeyCurveId)
{
    if (p_KeyCurveId.empty())
    {
        // secp224r1 is equal to RSA 2048 KeyBitLength. Refer RFC 5349
        log<level::WARNING>(
            "KeyCurveId is not given. Hence using default curve id",
            entry("DEFAULTKEYCURVEID=%s", DEFAULT_KEYCURVEID));
        p_KeyCurveId = DEFAULT_KEYCURVEID;
    }

    int ECGrp = OBJ_txt2nid(p_KeyCurveId.c_str());

    if (ECGrp == NID_undef)
    {
        log<level::ERR>(
            "Error occured during convert the curve id string format into NID",
            entry("KEYCURVEID=%s", p_KeyCurveId.c_str()));
        elog<InternalFailure>();
    }

    EC_KEY* EcKey = EC_KEY_new_by_curve_name(ECGrp);

    if (EcKey == NULL)
    {
        log<level::ERR>(
            "Error occured during create the EC_Key object from NID",
            entry("ECGROUP=%d", ECGrp));
        elog<InternalFailure>();
    }

    // If you want to save a key and later load it with
    // SSL_CTX_use_PrivateKey_file, then you must set the OPENSSL_EC_NAMED_CURVE
    // flag on the key.
    EC_KEY_set_asn1_flag(EcKey, OPENSSL_EC_NAMED_CURVE);

    int ret = EC_KEY_generate_key(EcKey);

    if (ret == 0)
    {
        EC_KEY_free(EcKey);
        log<level::ERR>("Error occured during generate EC key");
        elog<InternalFailure>();
    }

    EVP_PKEY_Ptr pKey(EVP_PKEY_new(), ::EVP_PKEY_free);
    ret = EVP_PKEY_assign_EC_KEY(pKey.get(), EcKey);
    if (ret == 0)
    {
        EC_KEY_free(EcKey);
        log<level::ERR>("Error occured during assign EC Key into EVP");
        elog<InternalFailure>();
    }

    return pKey;
}

void Manager::writePrivateKey(const EVP_PKEY_Ptr& pKey)
{
    log<level::INFO>("Writing private key to file");
    // write private key to file
    std::string path = fs::path(certInstallPath).parent_path();
    std::string privKeyPath = path + '/' + PRIV_KEY_FILE_NAME;

    FILE* fp = std::fopen(privKeyPath.c_str(), "w");
    if (fp == NULL)
    {
        log<level::ERR>("Error occured creating private key file");
        elog<InternalFailure>();
    }
    int ret = PEM_write_PrivateKey(fp, pKey.get(), NULL, NULL, 0, 0, NULL);
    std::fclose(fp);
    if (ret == 0)
    {
        log<level::ERR>("Error occured while writing private key to file");
        elog<InternalFailure>();
    }
}

void Manager::addEntry(X509_NAME* x509Name, const char* field,
                       const std::string& bytes)
{
    if (bytes.empty())
    {
        return;
    }
    int ret = X509_NAME_add_entry_by_txt(
        x509Name, field, MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(bytes.c_str()), -1, -1, 0);
    if (ret != 1)
    {
        log<level::ERR>("Unable to set entry", entry("FIELD=%s", field),
                        entry("VALUE=%s", bytes.c_str()));
        elog<InternalFailure>();
    }
}

void Manager::createCSRObject(const Status& status)
{
    if (csrPtr)
    {
        csrPtr.reset(nullptr);
    }
    auto csrObjectPath = objectPath + '/' + "csr";
    csrPtr = std::make_unique<CSR>(bus, csrObjectPath.c_str(),
                                   certInstallPath.c_str(), status);
}

void Manager::writeCSR(const std::string& filePath, const X509_REQ_Ptr& x509Req)
{
    if (fs::exists(filePath))
    {
        log<level::INFO>("Removing the existing file",
                         entry("FILENAME=%s", filePath.c_str()));
        if (!fs::remove(filePath.c_str()))
        {
            log<level::ERR>("Unable to remove the file",
                            entry("FILENAME=%s", filePath.c_str()));
            elog<InternalFailure>();
        }
    }

    FILE* fp = NULL;

    if ((fp = std::fopen(filePath.c_str(), "w")) == NULL)
    {
        log<level::ERR>("Error opening the file to write the CSR",
                        entry("FILENAME=%s", filePath.c_str()));
        elog<InternalFailure>();
    }

    int rc = PEM_write_X509_REQ(fp, x509Req.get());
    if (!rc)
    {
        log<level::ERR>("PEM write routine failed",
                        entry("FILENAME=%s", filePath.c_str()));
        std::fclose(fp);
        elog<InternalFailure>();
    }
    std::fclose(fp);
}

} // namespace certs
} // namespace phosphor
