#include "watch.hpp"

#include <sys/inotify.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
namespace phosphor
{
namespace certs
{

Watch::Watch(sdeventplus::Event& event, std::string& certFile, Callback cb) :
    callback(cb)
{
    using namespace phosphor::logging;
    namespace fs = std::filesystem;
    using InternalFailure =
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
    fd = inotify_init1(IN_NONBLOCK);
    if (-1 == fd)
    {
        auto error = errno;
        log<level::ERR>("inotify_init1 failed,",
                        entry("ERR=%s", std::strerror(error)));
        elog<InternalFailure>();
    }

    // watch for files created in the certificate path
    fs::path path = fs::path(certFile).parent_path();
    wd = inotify_add_watch(fd, path.c_str(), IN_CLOSE_WRITE);
    if (-1 == wd)
    {
        auto error = errno;
        close(fd);
        log<level::ERR>("inotify_add_watch failed,",
                        entry("ERR=%s", std::strerror(error)));
        elog<InternalFailure>();
    }
    ioPtr = std::make_unique<sdeventplus::source::IO>(
        event, fd, EPOLLIN,
        [this](sdeventplus::source::IO&, int fd, uint32_t revents) {
            log<level::INFO>("Callback method to load certificate file");
            callback();
            inotify_rm_watch(fd, wd);
            close(fd);
        });
}

Watch::~Watch()
{
    if (-1 != fd)
    {
        if (-1 != wd)
        {
            inotify_rm_watch(fd, wd);
        }
        close(fd);
    }
}
} // namespace certs
} // namespace phosphor
