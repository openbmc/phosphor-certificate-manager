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
namespace fs = std::filesystem;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

Watch::Watch(sdeventplus::Event& event, std::string& certFile, Callback cb) :
    event(event), callback(cb)
{
    log<level::INFO>("Adding watch ", entry("CERT_FILE=%s", certFile.c_str()));
    // get parent directory of certificate file to watch
    fs::path path = std::move(fs::path(certFile).parent_path());
    try
    {
        if (!fs::exists(path))
        {
            fs::create_directories(path);
        }
    }
    catch (fs::filesystem_error& e)
    {
        log<level::ERR>("Failed to create directory", entry("ERR=%s", e.what()),
                        entry("DIRECTORY=%s", path.c_str()));
        elog<InternalFailure>();
    }
    watchDir = path;
    watchFile = fs::path(certFile).filename();
    startWatch();
}

Watch::~Watch()
{
    stopWatch();
}

void Watch::startWatch()
{
    // stop any existing watch
    stopWatch();

    fd = inotify_init1(IN_NONBLOCK);
    if (-1 == fd)
    {
        log<level::ERR>("inotify_init1 failed,",
                        entry("ERR=%s", std::strerror(errno)));
        elog<InternalFailure>();
    }
    wd = inotify_add_watch(fd, watchDir.c_str(), IN_CLOSE_WRITE);
    if (-1 == wd)
    {
        close(fd);
        log<level::ERR>("inotify_add_watch failed,",
                        entry("ERR=%s", std::strerror(errno)),
                        entry("WATCH=%s", watchDir.c_str()));
        elog<InternalFailure>();
    }

    ioPtr = std::make_unique<sdeventplus::source::IO>(
        event, fd, EPOLLIN,
        [this](sdeventplus::source::IO&, int fd, uint32_t revents) {
            // check if expected event is received
            const int size = (sizeof(struct inotify_event)) + sizeof(uint32_t);
            std::array<char, size> buffer;
            read(fd, buffer.data(), size);
            struct inotify_event* notifyEvent =
                reinterpret_cast<struct inotify_event*>(&buffer[0]);
            if (watchFile == notifyEvent->name)
            {
                callback();
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
