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
using namespace phosphor::logging;

Watch::Watch(sdeventplus::Event& event, const std::string& watch,
             const std::string& certFile, uint32_t mask, bool recursive,
             Callback cb) :
    event(event),
    watch(watch), certFile(certFile), mask(mask), recursive(recursive),
    callback(cb)
{
    log<level::INFO>("Adding watch ", entry("WATCH=%s", watch.c_str()),
                     entry("CERT_FIE=%s", certFile.c_str()));
    startWatch();
}

Watch::~Watch()
{
    stopWatch();
}

void Watch::startWatch()
{
    namespace fs = std::filesystem;
    using InternalFailure =
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

    // stop if any existing watch
    stopWatch();

    fd = inotify_init1(IN_NONBLOCK);
    if (-1 == fd)
    {
        log<level::ERR>("inotify_init1 failed,",
                        entry("ERR=%s", std::strerror(errno)));
        elog<InternalFailure>();
    }
    wd = inotify_add_watch(fd, watch.c_str(), mask);
    if (-1 == wd)
    {
        close(fd);
        log<level::ERR>("inotify_add_watch failed,",
                        entry("ERR=%s", std::strerror(errno)),
                        entry("WATCH=%s", watch.c_str()));
        elog<InternalFailure>();
    }

    ioPtr = std::make_unique<sdeventplus::source::IO>(
        event, fd, EPOLLIN,
        [this](sdeventplus::source::IO&, int fd, uint32_t revents) {
            // Notification is recieved before the file is completely copied
            // so check if certificate file is existing
            if (fs::exists(certFile))
            {
                log<level::INFO>("inotify received invoking callback method");
                callback();

                if (recursive)
                {
                    // Recursive vall to restart the watch
                    log<level::INFO>("Restart recursive watch");
                    startWatch();
                }
            }
        });
}

void Watch::stopWatch()
{
    if (-1 != fd)
    {
        if (-1 != wd)
        {
            inotify_rm_watch(fd, wd);
        }
        close(fd);
    }
    if (ioPtr)
    {
        ioPtr.reset();
    }
}

} // namespace certs
} // namespace phosphor
