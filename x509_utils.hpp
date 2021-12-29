#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <memory>
#include <string>

namespace phosphor::certs
{

/** @brief Creates an X509 Store from the given certSrcPath
 *  Creates an X509 Store, adds a lookup file to the store from the given source
 * certificate, and returns it
 *  @param[in] certSrcPath - the file path to a list of trusted certificates
 *
 */
std::unique_ptr<X509_STORE, decltype(&::X509_STORE_free)>
    getX509Store(const std::string& certSrcPath);

/** @brief Loads Certificate file into the X509 structure.
 *  @param[in] filePath - Certificate and key full file path.
 *  @return pointer to the X509 structure.
 */
std::unique_ptr<X509, decltype(&::X509_free)>
    loadCert(const std::string& filePath);

/**
 * @brief Parses the certificate and throws error if certificate NotBefore date
 * is lt 1970
 * @param[in] cert Reference to certificate object uploaded
 * @return void
 */
void validateCertificateStartDate(X509& cert);

/**
 * @brief Validates the certificate against the trusted certificates store and
 * throws error if certificate is not valid
 * @param[in] x509Store Reference to trusted certificates store
 * @param[in] cert Reference to certificate to be validated
 * @return void
 */
void validateCertificateAgainstStore(X509_STORE& x509Store, X509& cert);

/**
 * @brief Validates the certificate can be used in an SSL context, otherwise,
 * throws errors
 * @param[in] cert Reference to certificate to be validated
 * @return void
 */
void validateCertificateInSSLContext(X509& cert);

/**
 * @brief Generates certificate ID based on provided certificate file.
 *
 * @param[in] cert - Certificate object.
 *
 * @return Certificate ID as formatted string.
 */
std::string generateCertId(X509& cert);

/**
 * @brief Copies the certificate from sourceFilePath to installFilePath
 *
 * @param[in] sourceFilePath - Path to the source file.
 * @param[in] sourceFilePath - Path to the destination file.
 *
 * @return void
 */
void copyCertificate(const std::string& sourceFilePath,
                     const std::string& installFilePath);

} // namespace phosphor::certs
