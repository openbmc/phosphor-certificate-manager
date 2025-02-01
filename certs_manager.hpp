#pragma once

#include "certificate.hpp"
#include "csr.hpp"
#include "watch.hpp"

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>

#include <sdbusplus/server/object.hpp>
#include <sdeventplus/source/child.hpp>
#include <sdeventplus/source/event.hpp>
#include <xyz/openbmc_project/Certs/CSR/Create/server.hpp>
#include <xyz/openbmc_project/Certs/Install/server.hpp>
#include <xyz/openbmc_project/Certs/InstallAll/server.hpp>
#include <xyz/openbmc_project/Certs/ReplaceAll/server.hpp>
#include <xyz/openbmc_project/Collection/DeleteAll/server.hpp>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace phosphor::certs
{

namespace internal
{
using ManagerInterface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Certs::server::Install,
    sdbusplus::xyz::openbmc_project::Certs::CSR::server::Create,
    sdbusplus::xyz::openbmc_project::Collection::server::DeleteAll,
    sdbusplus::xyz::openbmc_project::Certs::server::InstallAll,
    sdbusplus::xyz::openbmc_project::Certs::server::ReplaceAll>;
}

class Manager : public internal::ManagerInterface
{
  public:
    /* Define all of the basic class operations:
     *     Not allowed:
     *         - Default constructor is not possible due to member
     *           reference
     *         - Move operations due to 'this' being registered as the
     *           'context' with sdbus.
     *     Allowed:
     *         - copy
     *         - Destructor.
     */
    Manager() = delete;
    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;
    virtual ~Manager() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] event - sd event handler.
     *  @param[in] path - Path to attach at.
     *  @param[in] type - Type of the certificate.
     *  @param[in] unit - Unit consumed by this certificate.
     *  @param[in] installPath - Certificate installation path.
     */
    Manager(sdbusplus::bus_t& bus, sdeventplus::Event& event, const char* path,
            CertificateType type, const std::string& unit,
            const std::string& installPath);

    /** @brief Implementation for Install
     *  Replace the existing certificate key file with another
     *  (possibly CA signed) Certificate key file.
     *
     *  @param[in] filePath - Certificate key file path.
     *
     *  @return Certificate object path.
     */
    std::string install(const std::string filePath) override;

    /** @brief Implementation for InstallAll
     *  Install the authority list and restart the associated services.
     *
     *  @param[in] path - Path of the file that contains a list of root
     * certificates.
     *
     *  @return D-Bus object path to created objects.
     */
    std::vector<sdbusplus::message::object_path> installAll(
        std::string path) override;

    /** @brief Implementation for ReplaceAll
     *  Replace the current authority lists and restart the associated services.
     *
     *  @param[in] path - Path of file that contains multiple root certificates.
     *
     *  @return D-Bus object path to created objects.
     */
    std::vector<sdbusplus::message::object_path> replaceAll(
        std::string filePath) override;

    /** @brief Implementation for DeleteAll
     *  Delete all objects in the collection.
     */
    void deleteAll() override;

    /** @brief Delete the certificate.
     */
    void deleteCertificate(const Certificate* const certificate);

    /** @brief Replace the certificate.
     */
    void replaceCertificate(Certificate* const certificate,
                            const std::string& filePath);

    /** @brief Generate Private key and CSR file
     *  Generates the Private key file and CSR file based on the input
     *  parameters. Validation of the parameters is callers responsibility.
     *  At present supports only RSA algorithm type
     *
     *  @param[in] alternativeNames - Additional hostnames of the component that
     *      is being secured.
     *  @param[in] challengePassword - The challenge password to be applied to
     *      the certificate for revocation requests.
     *  @param[in] city - The city or locality of the organization making the
     *      request. For Example Austin
     *  @param[in] commonName - The fully qualified domain name of the component
     *      that is being secured.
     *  @param[in] contactPerson - The name of the user making the request.
     *  @param[in] country - The country of the organization making the request.
     *  @param[in] email - The email address of the contact within the
     *      organization making the request.
     *  @param[in] givenName - The given name of the user making the request.
     *  @param[in] initials - The initials of the user making the request.
     *  @param[in] keyBitLength - The length of the key in bits, if needed based
     *      on the value of the KeyPairAlgorithm parameter.
     *  @param[in] keyCurveId - The curve ID to be used with the key, if needed
     *      based on the value of the KeyPairAlgorithm parameter.
     *  @param[in] keyPairAlgorithm - The type of key pair for use with signing
     *      algorithms. Valid built-in algorithm names for private key
     *      generation are: RSA, DSA, DH and EC.
     *  @param[in] keyUsage - Key usage extensions define the purpose of the
     *      public key contained in a certificate. Valid Key usage extensions
     *      and its usage description.
     *      - ClientAuthentication: The public key is used for TLS WWW client
     *      authentication.
     *      - CodeSigning: The public key is used for the signing of executable
     *          code
     *      - CRLSigning: The public key is used for verifying signatures on
     *          certificate revocation lists (CLRs).
     *      - DataEncipherment: The public key is used for directly enciphering
     *          raw user data without the use of an intermediate symmetric
     *          cipher.
     *      - DecipherOnly: The public key could be used for deciphering data
     *          while performing key agreement.
     *      - DigitalSignature: The public key is used for verifying digital
     *          signatures, other than signatures on certificatesand CRLs.
     *      - EmailProtection: The public key is used for email protection.
     *      - EncipherOnly: Thepublic key could be used for enciphering data
     *          while performing key agreement.
     *      - KeyCertSign: The public key is used for verifying signatures on
     *          public key certificates.
     *      - KeyEncipherment: The public key is used for enciphering private or
     *          secret keys.
     *      - NonRepudiation: The public key is used to verify digital
     *          signatures, other than signatures on certificates and CRLs, and
     *          used to provide a non-repudiation service that protects against
     *          the signing entity falsely denying some action.
     *      - OCSPSigning: The public key is used for signing OCSP responses.
     *      - ServerAuthentication: The public key is used for TLS WWW server
     *          authentication.
     *      - Timestamping: The public key is used for binding the hash of an
     *          object to a time.
     *  @param[in] organization - The legal name of the organization. This
     *      should not be abbreviated and should include suffixes such as Inc,
     *      Corp, or LLC.For example, IBM Corp.
     *  @param[in] organizationalUnit - The name of the unit or division of the
     *      organization making the request.
     *  @param[in] state - The state or province where the organization is
     *      located. This should not be abbreviated. For example, Texas.
     *  @param[in] surname - The surname of the user making the request.
     *  @param[in] unstructuredName - The unstructured name of the subject.
     *
     *  @return path[std::string] - The object path of the D-Bus object
     *      representing CSR string. Note: For new CSR request will overwrite
     * the existing CSR in the system.
     */
    std::string generateCSR(
        std::vector<std::string> alternativeNames,
        std::string challengePassword, std::string city, std::string commonName,
        std::string contactPerson, std::string country, std::string email,
        std::string givenName, std::string initials, int64_t keyBitLength,
        std::string keyCurveId, std::string keyPairAlgorithm,
        std::vector<std::string> keyUsage, std::string organization,
        std::string organizationalUnit, std::string state, std::string surname,
        std::string unstructuredName) override;

    /** @brief Get reference to certificates' collection
     *
     *  @return Reference to certificates' collection
     */
    std::vector<std::unique_ptr<Certificate>>& getCertificates();

    /** @brief Systemd unit reload or reset helper function
     *  Reload if the unit supports it and use a restart otherwise.
     *  @param[in] unit - service need to reload.
     */
    virtual void reloadOrReset(const std::string& unit);

  private:
    void generateCSRHelper(
        std::vector<std::string> alternativeNames,
        std::string challengePassword, std::string city, std::string commonName,
        std::string contactPerson, std::string country, std::string email,
        std::string givenName, std::string initials, int64_t keyBitLength,
        std::string keyCurveId, std::string keyPairAlgorithm,
        std::vector<std::string> keyUsage, std::string organization,
        std::string organizationalUnit, std::string state, std::string surname,
        std::string unstructuredName);

    /** @brief Generate RSA Key pair and get private key from key pair
     *  @param[in]  keyBitLength - KeyBit length.
     *  @return     Pointer to RSA private key
     */
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> generateRSAKeyPair(
        const int64_t keyBitLength);

    /** @brief Generate EC Key pair and get private key from key pair
     *  @param[in]  p_KeyCurveId - Curve ID
     *  @return     Pointer to EC private key
     */
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> generateECKeyPair(
        const std::string& pKeyCurveId);

    /** @brief Write private key data to file
     *
     *  @param[in] pKey     - pointer to private key
     *  @param[in] privKeyFileName - private key filename
     */
    void writePrivateKey(
        const std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>& pKey,
        const std::string& privKeyFileName);

    /** @brief Add the specified CSR field with the data
     *  @param[in] x509Name - Structure used in setting certificate properties
     *  @param[in] field - field name
     *  @param[in] bytes - field value in bytes
     */
    void addEntry(X509_NAME* x509Name, const char* field,
                  const std::string& bytes);

    /** @brief Check if usage is extended key usage
     *  @param[in] usage - key usage value
     *  @return true if part of extended key usage
     */
    bool isExtendedKeyUsage(const std::string& usage);

    /** @brief Create CSR D-Bus object by reading the data in the CSR file
     *  @param[in] statis - SUCCESS/FAILURE In CSR generation.
     */
    void createCSRObject(const Status& status);

    /** @brief Write generated CSR data to file
     *
     *  @param[in] filePath - CSR file path.
     *  @param[in] x509Req - OpenSSL Request Pointer.
     */
    void writeCSR(
        const std::string& filePath,
        const std::unique_ptr<X509_REQ, decltype(&::X509_REQ_free)>& x509Req);

    /** @brief Load certificate
     *  Load certificate and create certificate object
     */
    void createCertificates();

    /** @brief Create RSA private key file
     *  Create RSA private key file by generating rsa key if not created
     */
    void createRSAPrivateKeyFile();

    /** @brief Getting RSA private key
     *  Getting RSA private key from generated file
     *  @param[in]  keyBitLength - Key bit length
     *  @return     Pointer to RSA key
     */
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> getRSAKeyPair(
        const int64_t keyBitLength);

    /** @brief Update certificate storage (remove outdated files, recreate
     * symbolic links, etc.).
     */
    void storageUpdate();

    /** @brief Check if provided certificate is unique across all certificates
     * on the internal list.
     *  @param[in] certFilePath - Path to the file with certificate for
     * uniqueness check.
     *  @param[in] certToDrop - Pointer to the certificate from the internal
     * list which should be not taken into account while uniqueness check.
     *  @return     Checking result. True if certificate is unique, false if
     * not.
     */
    bool isCertificateUnique(const std::string& certFilePath,
                             const Certificate* const certToDrop = nullptr);

    /** @brief sdbusplus handler */
    sdbusplus::bus_t& bus;

    // sdevent Event handle
    sdeventplus::Event& event;

    /** @brief object path */
    std::string objectPath;

    /** @brief Type of the certificate **/
    CertificateType certType;

    /** @brief Unit name associated to the service **/
    std::string unitToRestart;

    /** @brief Certificate file installation path **/
    std::string certInstallPath;

    /** @brief Collection of pointers to certificate */
    std::vector<std::unique_ptr<Certificate>> installedCerts;

    /** @brief pointer to CSR */
    std::unique_ptr<CSR> csrPtr = nullptr;

    /** @brief SDEventPlus child pointer added to event loop */
    std::unique_ptr<sdeventplus::source::Child> childPtr = nullptr;

    /** @brief Watch on self signed certificates */
    std::unique_ptr<Watch> certWatchPtr = nullptr;

    /** @brief Parent path i.e certificate directory path */
    std::filesystem::path certParentInstallPath;

    /** @brief Certificate ID pool */
    uint64_t certIdCounter = 1;
};
} // namespace phosphor::certs
