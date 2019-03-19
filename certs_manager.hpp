#pragma once
#include "config.h"

#include "certificate.hpp"

#include <openssl/x509v3.h>

#include <sdeventplus/source/child.hpp>
#include <sdeventplus/source/event.hpp>
#include <xyz/openbmc_project/Certs/CSR/Create/server.hpp>
#include <xyz/openbmc_project/Certs/CSR/server.hpp>
#include <xyz/openbmc_project/Certs/Install/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

namespace phosphor
{
namespace certs
{
using Install = sdbusplus::xyz::openbmc_project::Certs::server::Install;
using Delete = sdbusplus::xyz::openbmc_project::Object::server::Delete;
using CSRCreate = sdbusplus::xyz::openbmc_project::Certs::CSR::server::Create;
using CSRView = sdbusplus::xyz::openbmc_project::Certs::server::CSR;
using Ifaces = sdbusplus::server::object::object<Install, CSRCreate, Delete>;

using CSRViewIface = sdbusplus::server::object::object<CSRView>;

using X509_REQ_Ptr = std::unique_ptr<X509_REQ, decltype(&::X509_REQ_free)>;
class CSR;

enum class Status
{
    SUCCESS,
    FAILURE,
};

class Manager : public Ifaces
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
    Manager(const Manager&) = default;
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
    Manager(sdbusplus::bus::bus& bus, sdeventplus::Event& event,
            const char* path, const CertificateType& type,
            UnitsToRestart&& unit, CertInstallPath&& installPath);

    /** @brief Implementation for Install
     *  Replace the existing certificate key file with another
     *  (possibly CA signed) Certificate key file.
     *
     *  @param[in] filePath - Certificate key file path.
     */
    void install(const std::string filePath) override;

    /** @brief Delete the certificate (and possibly revert
     *         to a self-signed certificate).
     */
    void delete_() override;

    /** @brief Implementation for GenerateCSR
     *
     *  @param[in] alternativeNames - Additional hostnames of the component that
     *  is being secured.
     *  @param[in] challengePassword - The challenge password to be applied to
     *  the certificate for revocation requests.
     *  @param[in] city - The city or locality of the organization making the
     *  request. For Example Austin
     *  @param[in] commonName - The fully qualified domain name of the component
     *  that is being secured.
     *  @param[in] contactPerson - The name of the user making the request.
     *  @param[in] country - The country of the organization making the request.
     *  @param[in] email - The email address of the contact within the
     *  organization making the request. Email validtaion does not perform
     *  authentication to validate the email address. Only check the given email
     *  format is valid for an email address.
     *  @param[in] givenName - The given name of the user making the request.
     *  @param[in] initials - The initials of the user making the request.
     *  @param[in] keyBitLength - The length of the key in bits, if needed based
                   on the value of the KeyPairAlgorithm parameter.
     *  @param[in] keyCurveId - The curve ID to be used with the key, if needed
     *  based on the value of the KeyPairAlgorithm parameter.
     *  @param[in] keyPairAlgorithm - The type of key pair for use with signing
     *  algorithms. Valid built-in algorithm names for private key generation
     *  are: RSA and EC.
     *  @param[in] keyUsage - Key usage extensions define the purpose of the
     *  public key contained in a certificate. Valid Key usage extensions and
     *  its usage description.
     *  - ClientAuthentication: The public key is used for TLS WWW client
     *    authentication.
     *  - CodeSigning: The public key is used for the signing of executable code
     *  - CRLSigning: The public key is used for verifying signatures on
     *    certificate revocation lists (CLRs).
     *  - DataEncipherment: The public key is used for directly enciphering
     *    raw user data without the use of an intermediate symmetric cipher.
     *  - DecipherOnly: The public key could be used for deciphering data while
     *    performing key agreement.
     *  - DigitalSignature: The public key is used for verifying digital
     *    signatures, other than signatures on certificatesand CRLs.
     *  - EmailProtection: The public key is used for email protection.
     *  - EncipherOnly: Thepublic key could be used for enciphering data while
     *    performing key agreement.
     *  - KeyCertSign: The public key is used for verifying signatures on
     *    public key certificates.
     *  - KeyEncipherment: The public key is used for enciphering private or
     *    secret keys.
     *  - NonRepudiation: The public key is used to verify digital signatures,
     *    other than signatures on certificates and CRLs, and used to provide
     *    a non- repudiation service that protects against the signing entity
     *    falsely denying some action.
     *  - OCSPSigning: The public key is used for signing OCSP responses.
     *  - ServerAuthentication: The public key is used for TLS WWW server
     *    authentication.
     *  - Timestamping: The public key is used for binding the hash of an
     *    object to a time.
     *  @param[in] organization - The legal name of the organization. This
     *  should not be abbreviated and should include suffixes such as Inc,Corp,
     *  or LLC.For example, IBM Corp.
     *  @param[in] organizationalUnit - The name of the unit or division of the
     *  organization making the request.
     *  @param[in] state - The state or province where the organization is
     *  located. This should not be abbreviated. For example, Texas.
     *  @param[in] surname - The surname of the user making the request.
     *  @param[in] unstructuredName - The unstructured name of the subject.
     *
     *  @return path[std::string] - The object path of the D-Bus object
     *  representing CSR string. Note: For new CSR request will update the
     *  existing CSR in the system.
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

  private:
    /** @brief Add the specified CSR filed with the data
     *  @param[in] x509Name Structure used in setting certificate properties
     *  @param[in] field field name
     *  @param[in] bytes field value in bytes
     */
    void addEntry(X509_NAME* x509Name, const char* field,
                  const std::string& bytes);

    /** @brief Create CSR D-Bus object by reading the data in the CSR file
     */
    void createCSRObject();

    /** @brief Write generated CSR data to file
     *
     *  @param[in] filePath CSR file path.
     *  @param[in] x509Req OpenSSL Request Pointer.
     */
    void writeCSR(const std::string& filePath, const X509_REQ_Ptr& x509Req);

    /** @brief sdbusplus handler */
    sdbusplus::bus::bus& bus;

    // sdevent Event handle
    sdeventplus::Event& event;

    /** @brief object path */
    std::string objectPath;

    /** @brief Type of the certificate **/
    CertificateType certType;

    /** @brief Unit name associated to the service **/
    UnitsToRestart unitToRestart;

    /** @brief Certificate file installation path **/
    CertInstallPath certInstallPath;

    /** @brief pointer to certificate */
    std::unique_ptr<Certificate> certificatePtr = nullptr;

    /** @brief pointer to CSR */
    std::unique_ptr<CSR> csrPtr = nullptr;

    /** @brief SDEventPlus child pointer added to event loop */
    std::unique_ptr<sdeventplus::source::Child> childPtr;

    /** @brief Status of GenerateCSR request */
    Status csrStatus;
};

/** @class CSR
 *  @brief To view CSR certificates
 */
class CSR : public CSRViewIface
{
  public:
    CSR() = delete;
    ~CSR() = default;
    CSR(const CSR&) = delete;
    CSR& operator=(const CSR&) = delete;
    CSR(CSR&&) = default;
    CSR& operator=(CSR&&) = default;

    /** @brief Constructor to put object onto bus at a D-Bus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - The D-Bus object path to attach at.
     *  @param[in] installPath - Certificate installation path.
     *  @param[in] status - Status of Generate CSR request
     */
    CSR(sdbusplus::bus::bus& bus, const char* path,
        CertInstallPath&& installPath, const Status& status);
    /** @brief Return CSR
     */
    std::string cSR() override;

  private:
    /** @brief sdbusplus handler */
    sdbusplus::bus::bus& bus;

    /** @brief object path */
    std::string objectPath;

    /** @brief Certificate file installation path **/
    CertInstallPath certInstallPath;

    /** @brief Status of GenerateCSR request */
    Status csrStatus;
};
} // namespace certs
} // namespace phosphor
