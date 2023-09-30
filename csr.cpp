#include "config.h"

#include "csr.hpp"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Certs/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <cstdio>
#include <filesystem>
#include <memory>
#include <utility>

namespace phosphor::certs
{

using ::phosphor::logging::elog;
using ::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
namespace fs = std::filesystem;

using X509ReqPtr = std::unique_ptr<X509_REQ, decltype(&::X509_REQ_free)>;
using BIOPtr = std::unique_ptr<BIO, decltype(&::BIO_free_all)>;

CSR::CSR(sdbusplus::bus_t& bus, const char* path, std::string&& installPath,
         const Status& status) :
    internal::CSRInterface(bus, path,
                           internal::CSRInterface::action::defer_emit),
    objectPath(path), certInstallPath(std::move(installPath)), csrStatus(status)
{
    // Emit deferred signal.
    this->emit_object_added();
}

std::string CSR::csr()
{
    if (csrStatus == Status::failure)
    {
        lg2::error("Failure in Generating CSR");
        elog<InternalFailure>();
    }
    fs::path csrFilePath = certInstallPath;
    csrFilePath = csrFilePath.parent_path() / defaultCSRFileName;
    if (!fs::exists(csrFilePath))
    {
        lg2::error("CSR file doesn't exists, FILENAME:{FILENAME}", "FILENAME",
                   csrFilePath);
        elog<InternalFailure>();
    }

    FILE* fp = std::fopen(csrFilePath.c_str(), "r");
    X509ReqPtr x509Req(PEM_read_X509_REQ(fp, nullptr, nullptr, nullptr),
                       ::X509_REQ_free);
    if (x509Req == nullptr || fp == nullptr)
    {
        if (fp != nullptr)
        {
            std::fclose(fp);
        }
        lg2::error("ERROR occurred while reading CSR file, FILENAME:{FILENAME}",
                   "FILENAME", csrFilePath);
        elog<InternalFailure>();
    }
    std::fclose(fp);

    BIOPtr bio(BIO_new(BIO_s_mem()), ::BIO_free_all);
    int ret = PEM_write_bio_X509_REQ(bio.get(), x509Req.get());
    if (ret <= 0)
    {
        lg2::error("Error occurred while calling PEM_write_bio_X509_REQ");
        elog<InternalFailure>();
    }

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    std::string pem(mem->data, mem->length);
    return pem;
}

} // namespace phosphor::certs
