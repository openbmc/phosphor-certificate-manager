#include "certificate.hpp"

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <unistd.h>

#include <filesystem>
#include <phosphor-logging/elog-errors.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
namespace phosphor
{
namespace certs
{
using namespace phosphor::logging;
namespace fs = std::filesystem;

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
// Refer to schema 2018.3
// http://redfish.dmtf.org/schemas/v1/Certificate.json#/definitions/KeyUsage for
// supported KeyUsage types in redfish
// Refer to
// https://github.com/openssl/openssl/blob/master/include/openssl/x509v3.h for
// key usage bit fields
std::map<uint8_t, std::string> keyUsageToRfStr = {
    {KU_DIGITAL_SIGNATURE, "DigitalSignature"},
    {KU_NON_REPUDIATION, "NonRepudiation"},
    {KU_KEY_ENCIPHERMENT, "KeyEncipherment"},
    {KU_DATA_ENCIPHERMENT, "DataEncipherment"},
    {KU_KEY_AGREEMENT, "KeyAgreement"},
    {KU_KEY_CERT_SIGN, "KeyCertSign"},
    {KU_CRL_SIGN, "CRLSigning"},
    {KU_ENCIPHER_ONLY, "EncipherOnly"},
    {KU_DECIPHER_ONLY, "DecipherOnly"}};

// Refer to schema 2018.3
// http://redfish.dmtf.org/schemas/v1/Certificate.json#/definitions/KeyUsage for
// supported Extended KeyUsage types in redfish
std::map<uint8_t, std::string> extendedKeyUsageToRfStr = {
    {NID_server_auth, "ServerAuthentication"},
    {NID_client_auth, "ClientAuthentication"},
    {NID_email_protect, "EmailProtection"},
    {NID_OCSP_sign, "OCSPSigning"},
    {NID_ad_timeStamping, "Timestamping"},
    {NID_code_sign, "CodeSigning"}};

Certificate::Certificate(sdbusplus::bus::bus& bus, sdeventplus::Event& event,
                         const std::string& objPath,
                         const CertificateType& type,
                         const UnitsToRestart& unit,
                         const CertInstallPath& installPath,
                         CertWatchPtr& certWatchPtr) :
    CertIfaces(bus, objPath.c_str(), true),
    bus(bus), event(event), objectPath(objPath), certType(type),
    unitToRestart(unit), certInstallPath(installPath), keyHandler(type),
    certWatchPtr(certWatchPtr)
{
    // Parse the certificate file and populate properties
    populateProperties();

    this->emit_object_added();
}

void Certificate::replace(const std::string filePath)
{
    log<level::ERR>("Certificate replace",
                    entry("FILE_NAME=%s", filePath.c_str()));
    if (!fs::exists(filePath))
    {
        log<level::ERR>("Input file not existing",
                        entry("FILE_NAME=%s", filePath.c_str()));
        elog<InternalFailure>();
        return;
    }

    // validate the certificate
    keyHandler.verify(filePath);

    // stop watch as user is copying the certificate
    certWatchPtr->stopWatch();

    // Copy the certificate to the installation path
    try
    {
        fs::copy_file(filePath, certInstallPath,
                      fs::copy_options::overwrite_existing);
    }
    catch (fs::filesystem_error& e)
    {
        log<level::ERR>("Failed to copy certificate", entry("ERR=%s", e.what()),
                        entry("SRC=%s", filePath.c_str()),
                        entry("DST=%s", certInstallPath.c_str()));
        elog<InternalFailure>();
    }

    // Parse the certificate file and populate properties
    populateProperties();

    // as certificate is replaced notify consumers to reload SSL context
    reloadOrReset();

    // restart watch to check for files being over-written by other apps
    certWatchPtr->startWatch();
}

void Certificate::populateProperties()
{
    using BIO_MEM_Ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
    using BUF_MEM_Ptr = std::unique_ptr<BUF_MEM, decltype(&::BUF_MEM_free)>;
    using ASN1_TIME_ptr =
        std::unique_ptr<ASN1_TIME, decltype(&ASN1_STRING_free)>;
    X509_Ptr cert = std::move(keyHandler.loadCert(certInstallPath));
    // Update properties if no error thrown
    BIO_MEM_Ptr certBio(BIO_new(BIO_s_mem()), BIO_free);
    PEM_write_bio_X509(certBio.get(), cert.get());
    BUF_MEM_Ptr certBuf(BUF_MEM_new(), BUF_MEM_free);
    BUF_MEM* buf = certBuf.get();
    BIO_get_mem_ptr(certBio.get(), &buf);
    std::string certStr(buf->data, buf->length);
    CertificateIface::certificateString(certStr);

    static const int maxKeySize = 4096;
    char subBuffer[maxKeySize] = {0};
    BIO_MEM_Ptr subBio(BIO_new(BIO_s_mem()), BIO_free);
    // This pointer cannot be freed independantly.
    X509_NAME* sub = X509_get_subject_name(cert.get());
    X509_NAME_print_ex(subBio.get(), sub, 0, XN_FLAG_SEP_COMMA_PLUS);
    BIO_read(subBio.get(), subBuffer, maxKeySize);
    CertificateIface::subject(subBuffer);

    char issuerBuffer[maxKeySize] = {0};
    BIO_MEM_Ptr issuerBio(BIO_new(BIO_s_mem()), BIO_free);
    // This pointer cannot be freed independantly.
    X509_NAME* issuer_name = X509_get_issuer_name(cert.get());
    X509_NAME_print_ex(issuerBio.get(), issuer_name, 0, XN_FLAG_SEP_COMMA_PLUS);
    BIO_read(issuerBio.get(), issuerBuffer, maxKeySize);
    CertificateIface::issuer(issuerBuffer);

    std::vector<std::string> keyUsageList;
    ASN1_BIT_STRING* usage;

    // Go through each usage in the bit string and convert to
    // corresponding string value
    if ((usage = static_cast<ASN1_BIT_STRING*>(
             X509_get_ext_d2i(cert.get(), NID_key_usage, NULL, NULL))))
    {
        for (auto i = 0; i < usage->length; ++i)
        {
            for (auto& x : keyUsageToRfStr)
            {
                if (x.first & usage->data[i])
                {
                    keyUsageList.push_back(x.second);
                    break;
                }
            }
        }
    }

    EXTENDED_KEY_USAGE* extUsage;
    if ((extUsage = static_cast<EXTENDED_KEY_USAGE*>(
             X509_get_ext_d2i(cert.get(), NID_ext_key_usage, NULL, NULL))))
    {
        for (int i = 0; i < sk_ASN1_OBJECT_num(extUsage); i++)
        {
            keyUsageList.push_back(extendedKeyUsageToRfStr[OBJ_obj2nid(
                sk_ASN1_OBJECT_value(extUsage, i))]);
        }
    }
    CertificateIface::keyUsage(keyUsageList);

    int days = 0;
    int secs = 0;

    ASN1_TIME_ptr epoch(ASN1_TIME_new(), ASN1_STRING_free);
    // Set time to 12:00am GMT, Jan 1 1970
    ASN1_TIME_set_string(epoch.get(), "700101120000Z");

    static const int dayToSeconds = 24 * 60 * 60;
    ASN1_TIME* notAfter = X509_get_notAfter(cert.get());
    ASN1_TIME_diff(&days, &secs, epoch.get(), notAfter);
    CertificateIface::validNotAfter((days * dayToSeconds) + secs);

    ASN1_TIME* notBefore = X509_get_notBefore(cert.get());
    ASN1_TIME_diff(&days, &secs, epoch.get(), notBefore);
    CertificateIface::validNotBefore((days * dayToSeconds) + secs);
}

void Certificate::reloadOrReset()
{
    if (!unitToRestart.empty())
    {
        constexpr auto SYSTEMD_SERVICE = "org.freedesktop.systemd1";
        constexpr auto SYSTEMD_OBJ_PATH = "/org/freedesktop/systemd1";
        constexpr auto SYSTEMD_INTERFACE = "org.freedesktop.systemd1.Manager";
        try
        {
            auto method =
                bus.new_method_call(SYSTEMD_SERVICE, SYSTEMD_OBJ_PATH,
                                    SYSTEMD_INTERFACE, "ReloadOrRestartUnit");
            method.append(unitToRestart, "replace");
            bus.call_noreply(method);
        }
        catch (const sdbusplus::exception::SdBusError& e)
        {
            log<level::ERR>("Failed to reload or restart service",
                            entry("ERR=%s", e.what()),
                            entry("UNIT=%s", unitToRestart.c_str()));
            elog<InternalFailure>();
        }
    }
}
} // namespace certs
} // namespace phosphor
