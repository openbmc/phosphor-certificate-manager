#pragma once

#include <openssl/x509.h>

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
namespace phosphor
{
namespace certs
{
// RAII support for openSSL functions.
using X509_Ptr = std::unique_ptr<X509, decltype(&::X509_free)>;
using CertType = std::string;
using VerifyFunc = std::function<void(const std::string&)>;

// Supported Types.
constexpr char const* SERVER = "server";
constexpr char const* CLIENT = "client";
constexpr char const* AUTHORITY = "authority";

/** @class KeyHandler
 *
 *  @brief Class to validate certificate file
 *
 *  Provides generic methods to validate certificate file
 */
class KeyHandler
{
  public:
    KeyHandler() = delete;
    KeyHandler(const KeyHandler&) = delete;
    KeyHandler& operator=(const KeyHandler&) = delete;
    KeyHandler(KeyHandler&&) = delete;
    KeyHandler& operator=(KeyHandler&&) = delete;
    virtual ~KeyHandler() = default;

    /** @brief Certificate verification handler
     *  @param[in] certType - Type of the certificate
     */
    KeyHandler(const CertType& certType);

    /** @brief Validate and Replace/Install the certificate file
     *  Install/Replace the existing certificate file with another
     *  (possibly CA signed) Certificate file.
     *  @param[in] filePath - Certificate file path.
     */
    void verify(const std::string& filePath);

    /** @brief Load Certificate file into the X509 structre.
     *  @param[in] filePath - Certificate and key full file path.
     *  @return pointer to the X509 structure.
     */
    X509_Ptr loadCert(const std::string& filePath);

  private:
    /** @brief Public/Private key compare function.
     *         Comparing private key against certificate public key
     *         from input .pem file.
     *  @param[in] filePath - Certificate and key full file path.
     */
    void compareKeys(const std::string& filePath);

    /** @brief Check and append private key to the uploaded certificate file
     *  @param[in] filePath - Certificate file path.
     *  @return None
     */
    void appendPrivateKey(const std::string& filePath);

    /** @brief Type specific function pointer map for comparing keys */
    std::unordered_map<CertType, VerifyFunc> compareKeyMap;

    /** @brief Type specific function pointer map for appending private key */
    std::unordered_map<CertType, VerifyFunc> appendKeyMap;

    /** @brief Type of the certificate*/
    CertType certType;
};
} // namespace certs
} // namespace phosphor
