#pragma once

#include <memory>
#include <openssl/x509.h>

// RAII support for openSSL functions.
using ASN1_TIME_ptr = std::unique_ptr<ASN1_TIME, decltype(&ASN1_STRING_free)>;
using BIGNUM_Ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using BIO_Ptr = std::unique_ptr<BIO, decltype(&::BIO_free_all)>;
using BIO_MEM_Ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;
using BUF_MEM_Ptr = std::unique_ptr<BUF_MEM, decltype(&::BUF_MEM_free)>;
using EVP_PKEY_Ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using X509_Ptr = std::unique_ptr<X509, decltype(&::X509_free)>;
using X509_LOOKUP_Ptr =
    std::unique_ptr<X509_LOOKUP, decltype(&::X509_LOOKUP_free)>;
using X509_REQ_Ptr = std::unique_ptr<X509_REQ, decltype(&::X509_REQ_free)>;
using X509_STORE_CTX_Ptr =
    std::unique_ptr<X509_STORE_CTX, decltype(&::X509_STORE_CTX_free)>;
