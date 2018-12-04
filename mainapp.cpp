/**
 * Copyright © 2018 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"

#include "argument.hpp"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <experimental/filesystem>
#include <iostream>
#include <locale>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <string>

const char* SERVER = "server";
const char* CLIENT = "client";
const char* AUTHORITY = "authority";

std::string type;
std::string endpoint;
std::string path;
std::string unit;
std::shared_ptr<sdbusplus::asio::connection> conn;

static void ExitWithError(const char* err, char** argv)
{
    phosphor::certs::util::ArgumentParser::usage(argv);
    std::cerr << std::endl;
    std::cerr << "ERROR: " << err << std::endl;
    exit(EXIT_FAILURE);
}

inline void capitalize(std::string& s)
{
    s[0] = std::toupper(s[0]);
}

// RAII support for openSSL functions.

using BIO_MEM_Ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using X509_Ptr = std::unique_ptr<X509, decltype(&::X509_free)>;
using X509_STORE_CTX_Ptr =
    std::unique_ptr<X509_STORE_CTX, decltype(&::X509_STORE_CTX_free)>;
using X509_LOOKUP_Ptr =
    std::unique_ptr<X509_LOOKUP, decltype(&::X509_LOOKUP_free)>;
using EVP_PKEY_Ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;

inline void reloadOrReset(const std::string& unit)
{
    conn->async_method_call(
        [unit](boost::system::error_code ec) {
            if (ec)
            {
                std::cout << "Failed to restart unit " << unit << " " << ec
                          << "\n";
                return;
            }
        },
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "ReloadOrRestartUnit",
        "/org/openbmc/control", unit, "replace");
}

inline void copy(const std::string& src, const std::string& dst)
{
    try
    {
        std::experimental::filesystem::path path =
            std::experimental::filesystem::path(dst).parent_path();
        // create dst path folder by default
        std::experimental::filesystem::create_directories(path);
        std::experimental::filesystem::copy_file(
            src, dst,
            std::experimental::filesystem::copy_options::overwrite_existing);
    }
    catch (std::experimental::filesystem::filesystem_error& e)
    {
        /* log<level::ERR>("Failed to copy certificate", entry("ERR=%s",
           e.what()), entry("SRC=%s", src.c_str()), entry("DST=%s",
           dst.c_str()));*/
        // // elog<InternalFailure>();
    }
}

inline X509_Ptr loadCert(const std::string& filePath)
{
    // Read Certificate file
    X509_Ptr cert(X509_new(), ::X509_free);
    if (!cert)
    {
        /* log<level::ERR>("Error occured during X509_new call",
                        entry("FILE=%s", filePath.c_str()),
                        entry("ERRCODE=%lu", ERR_get_error()));*/
        // // elog<InternalFailure>();
    }

    BIO_MEM_Ptr bioCert(BIO_new_file(filePath.c_str(), "rb"), ::BIO_free);
    if (!bioCert)
    {
        /*log<level::ERR>("Error occured during BIO_new_file call",
                        entry("FILE=%s", filePath.c_str())); */
        // // elog<InternalFailure>();
    }

    X509* x509 = cert.get();
    if (!PEM_read_bio_X509(bioCert.get(), &x509, nullptr, nullptr))
    {
        /* log<level::ERR>("Error occured during PEM_read_bio_X509 call",
                        entry("FILE=%s", filePath.c_str()));*/
        // // elog<InternalFailure>();
    }
    return cert;
}

inline int32_t verifyCert(const std::string& filePath)
{
    std::experimental::filesystem::path file(filePath);
    if (!std::experimental::filesystem::exists(file))
    {
        // log<level::ERR>("File is Missing", entry("FILE=%s",
        // filePath.c_str()));
        // // elog<InternalFailure>();
    }

    try
    {
        if (std::experimental::filesystem::file_size(filePath) == 0)
        {
            // file is empty
            /* log<level::ERR>("File is empty",
                            entry("FILE=%s", filePath.c_str()));
            // elog<InvalidCertificate>(Reason("File is empty"));*/
        }
    }
    catch (const std::experimental::filesystem::filesystem_error& e)
    {
        // Log Error message
        // log<level::ERR>(e.what(), entry("FILE=%s", filePath.c_str()));
        // // elog<InternalFailure>();
    }

    // Defining store object as RAW to avoid double free.
    // X509_LOOKUP_free free up store object.
    // Create an empty X509_STORE structure for certificate validation.
    auto x509Store = X509_STORE_new();
    if (!x509Store)
    {
        // log<level::ERR>("Error occured during X509_STORE_new call");
        // // elog<InternalFailure>();
    }

    OpenSSL_add_all_algorithms();

    // ADD Certificate Lookup method.
    X509_LOOKUP_Ptr lookup(X509_STORE_add_lookup(x509Store, X509_LOOKUP_file()),
                           ::X509_LOOKUP_free);
    if (!lookup)
    {
        // Normally lookup cleanup function interanlly does X509Store cleanup
        // Free up the X509Store.
        X509_STORE_free(x509Store);
        // log<level::ERR>("Error occured during X509_STORE_add_lookup call");
        // // elog<InternalFailure>();
    }
    // Load Certificate file.
    int32_t rc = X509_LOOKUP_load_file(lookup.get(), filePath.c_str(),
                                       X509_FILETYPE_PEM);
    if (rc != 1)
    {
        /* log<level::ERR>("Error occured during X509_LOOKUP_load_file call",
                        entry("FILE=%s", filePath.c_str()));
                        // elog<InvalidCertificate>(Reason("Invalid certificate
                        // file format")); */
    }

    // Load Certificate file into the X509 structre.
    X509_Ptr cert = std::move(loadCert(filePath));
    X509_STORE_CTX_Ptr storeCtx(X509_STORE_CTX_new(), ::X509_STORE_CTX_free);
    if (!storeCtx)
    {
        /* log<level::ERR>("Error occured during X509_STORE_CTX_new call",
                        entry("FILE=%s", filePath.c_str()));
                        // // elog<InternalFailure>();*/
    }

    rc = X509_STORE_CTX_init(storeCtx.get(), x509Store, cert.get(), NULL);
    if (rc != 1)
    {
        /* log<level::ERR>("Error occured during X509_STORE_CTX_init call",
                        entry("FILE=%s", filePath.c_str()));
                        // // elog<InternalFailure>();*/
    }

    // Set time to current time.
    auto locTime = time(nullptr);

    X509_STORE_CTX_set_time(storeCtx.get(), X509_V_FLAG_USE_CHECK_TIME,
                            locTime);

    rc = X509_verify_cert(storeCtx.get());
    if (rc == 1)
    {
        return X509_V_OK;
    }
    else if (rc != 0)
    {
        /* log<level::ERR>("Error occured during X509_verify_cert call",
                        entry("FILE=%s", filePath.c_str()));*/
        // // elog<InternalFailure>();
        return X509_V_OK;
    }
    rc = X509_STORE_CTX_get_error(storeCtx.get());
    /* log<level::ERR>("Certificate verification failed",
                    entry("FILE=%s", filePath.c_str()),
                    entry("ERRCODE=%d", errCode));*/
    return rc;
}

inline bool
    certStringValid(const std::string& certificate,
                    std::shared_ptr<sdbusplus::asio::dbus_interface> iface)
{
    OpenSSL_add_all_algorithms();
    BIO* bio = nullptr;
    X509* cert = nullptr;
    X509_STORE* store = nullptr;
    X509_STORE_CTX* ctx = nullptr;
    bool valid = false;

    bio = BIO_new_mem_buf((void*)certificate.data(), certificate.size());
    if (bio != nullptr)
    {
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (cert == nullptr)
        {
            store = X509_STORE_new();
            if (store != nullptr)
            {
                ctx = X509_STORE_CTX_new();
                if (ctx != nullptr)
                {
                    X509_STORE_CTX_init(ctx, store, cert, NULL);
                    int rc = X509_verify_cert(ctx);
                    if (!((rc == X509_V_OK) ||
                          (rc == X509_V_ERR_CERT_NOT_YET_VALID) ||
                          (rc == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ||
                          (rc == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) ||
                          (rc ==
                           X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) ||
                          (rc == X509_V_ERR_CERT_UNTRUSTED) ||
                          (rc == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)))
                    {
                        valid = true;
                        // ASN1_INTEGER* asn1_serial =
                        // X509_get_serialNumber(cert);
                        iface->set_property("Subject", "foobar");
                        iface->set_property("SerialNumber", "foobar");
                        iface->set_property("ValidNotAfter", "foobar");
                        iface->set_property("ValidNotBefore", "foobar");
                    }
                }
            }
        }
    }

    if (ctx)
        X509_STORE_CTX_free(ctx);
    if (store)
        X509_STORE_free(store);
    if (cert)
        X509_free(cert);
    if (bio)
        BIO_free(bio);
    return valid;
}

inline bool compareKeys(const std::string& filePath)
{
    X509_Ptr cert(X509_new(), ::X509_free);
    if (!cert)
    {
        /* log<level::ERR>("Error occured during X509_new call",
                        entry("FILE=%s", filePath.c_str()),
                        entry("ERRCODE=%lu", ERR_get_error()));
                        // // elog<InternalFailure>();*/
    }

    BIO_MEM_Ptr bioCert(BIO_new_file(filePath.c_str(), "rb"), ::BIO_free);
    if (!bioCert)
    {
        /* log<level::ERR>("Error occured during BIO_new_file call",
                        entry("FILE=%s", filePath.c_str()));
                        // // elog<InternalFailure>();*/
    }

    X509* x509 = cert.get();
    PEM_read_bio_X509(bioCert.get(), &x509, nullptr, nullptr);

    EVP_PKEY_Ptr pubKey(X509_get_pubkey(cert.get()), ::EVP_PKEY_free);
    if (!pubKey)
    {
        /* log<level::ERR>("Error occurred during X509_get_pubkey",
                        entry("FILE=%s", filePath.c_str()),
                        entry("ERRCODE=%lu", ERR_get_error()));
                        // elog<InvalidCertificate>(Reason("Failed to get public
                        // key info"));*/
    }

    BIO_MEM_Ptr keyBio(BIO_new(BIO_s_file()), ::BIO_free);
    if (!keyBio)
    {
        /* log<level::ERR>("Error occured during BIO_s_file call",
                        entry("FILE=%s", filePath.c_str()));
                        // // elog<InternalFailure>();*/
    }
    BIO_read_filename(keyBio.get(), filePath.c_str());

    EVP_PKEY_Ptr priKey(
        PEM_read_bio_PrivateKey(keyBio.get(), nullptr, nullptr, nullptr),
        ::EVP_PKEY_free);

    if (!priKey)
    {
        /* log<level::ERR>("Error occurred during PEM_read_bio_PrivateKey",
                        entry("FILE=%s", filePath.c_str()),
                        entry("ERRCODE=%lu", ERR_get_error()));
                        // elog<InvalidCertificate>(Reason("Failed to get
                        // private key info"));*/
    }

    int32_t rc = EVP_PKEY_cmp(priKey.get(), pubKey.get());
    if (rc != 1)
    {
        /* log<level::ERR>("Private key is not matching with Certificate",
                        entry("FILE=%s", filePath.c_str()),
                        entry("ERRCODE=%d", rc));*/
        return false;
    }

    return true;
}

inline void deleteCertificate(std::string& certPath)
{
    if (!std::experimental::filesystem::remove(certPath))
    {
        /* log<level::INFO>("Certificate file not found!",
                         entry("PATH=%s", certPath.c_str()));*/
    }
    else if (!unit.empty())
    {
        reloadOrReset(unit);
    }
}

inline void install(const std::string& filePath)
{
    // Verify the certificate file
    int32_t rc = verifyCert(path);
    // Allow certificate upload, for "certificate is not yet valid" and
    // trust chain related errors.
    if (!((rc == X509_V_OK) || (rc == X509_V_ERR_CERT_NOT_YET_VALID) ||
          (rc == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ||
          (rc == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) ||
          (rc == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) ||
          (rc == X509_V_ERR_CERT_UNTRUSTED) ||
          (rc == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE) ||
          (rc == X509_V_ERR_CERT_HAS_EXPIRED)))
    {
        if (rc == X509_V_ERR_CERT_HAS_EXPIRED)
        {
            // elog<InvalidCertificate>(Reason("Expired Certificate"));
        }
        // Loging general error here.
        // elog<InvalidCertificate>(Reason("Certificate validation failed"));
    }

    if (type == SERVER || type == CLIENT)
    {
        if (!compareKeys(filePath))
        {
            /* elog<InvalidCertificate>(
                Reason("Private key does not match the Certificate"));*/
        };
    }
    else
    {
        // log<level::ERR>("Unsupported Type", entry("TYPE=%s", type.c_str()));
        // // elog<InternalFailure>();
    }

    // Copy the certificate file
    copy(path, filePath);

    if (!unit.empty())
    {
        reloadOrReset(unit);
    }
}

int main(int argc, char** argv)
{
    // Read arguments.
    phosphor::certs::util::ArgumentParser options(argc, argv);

    // Parse arguments
    type = std::move(options["type"]);
    if (type != SERVER && type != CLIENT && type != AUTHORITY)
    {
        ExitWithError("type not specified or invalid.", argv);
    }

    endpoint = std::move(options["endpoint"]);
    if (endpoint.empty())
    {
        ExitWithError("endpoint not specified.", argv);
    }

    path = std::move(options["path"]);
    if (path.empty())
    {
        ExitWithError("path not specified.", argv);
    }

    // unit is an optional parameter
    unit = std::move(options["unit"]);

    std::string objPath = std::string(OBJPATH) + '/' + type + '/' + endpoint;

    // Adjusting Interface name as per std convention
    capitalize(type);
    capitalize(endpoint);
    std::string busName = std::string(BUSNAME) + '.' + type + '.' + endpoint;
    boost::asio::io_service io;
    conn = std::make_shared<sdbusplus::asio::connection>(io);
    conn->request_name(busName.c_str());

    sdbusplus::asio::object_server server(conn);
    std::shared_ptr<sdbusplus::asio::dbus_interface> installIface =
        server.add_interface(objPath.c_str(),
                             "xyz.openbmc_project.Cert.Install");

    installIface->register_method("Install", install);

    installIface->initialize();

    std::shared_ptr<sdbusplus::asio::dbus_interface> certificateInterface =
        server.add_interface(objPath.c_str(),
                             "xyz.openbmc_project.Cert.Certificate");

    certificateInterface->register_property(
        "Issuer", std::string(""),
        [](const std::string& req, std::string& propertyValue) {
            propertyValue = req;
            return 1;
        },
        [](const std::string& property) { return property; });

    certificateInterface->register_property("Subject", std::string(""));
    certificateInterface->register_property("SerialNumber", std::string(""));
    certificateInterface->register_property("ValidNotAfter", std::string(""));
    certificateInterface->register_property("ValidNotBefore", std::string(""));

    certificateInterface->register_property(
        "Certificate", std::string(""),
        [certificateInterface](const std::string& requested,
                               std::string& certificateValue) {
            // allow setting empty values to "clear"
            if (!certificateValue.empty())
            {
                if (!certStringValid(requested, certificateInterface))
                {
                    return -1;
                }
            }
            certificateValue = requested;
            return 1;
        });
    io.run();
    return 0;
}
