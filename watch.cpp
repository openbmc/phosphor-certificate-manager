#include "watch.hpp"

#include <sys/inotify.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor::certs
{

using ::phosphor::logging::elog;
using ::phosphor::logging::entry;
using ::phosphor::logging::level;
using ::phosphor::logging::log;
using ::sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
namespace fs = std::filesystem;

Watch::Watch(sdeventplus::Event& event, std::string& certFile, Callback cb) :
    event(event), callback(cb)
{
    // get parent directory of certificate file to watch
    fs::path path = fs::path(certFile).parent_path();
    try
    {
        if (!fs::exists(path))
        {
            fs::create_directories(path);
        }
    }
    catch (const fs::filesystem_error& e)
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
        event, fd, EPOLLIN, [this](sdeventplus::source::IO&, int fd, uint32_t) {
            constexpr int size = sizeof(struct inotify_event) + NAME_MAX + 1;
            std::array<char, size> buffer{};
            int length = read(fd, buffer.data(), buffer.size());
            if (length >= static_cast<int>(sizeof(struct inotify_event)))
            {
                struct inotify_event* notifyEvent =
                    reinterpret_cast<struct inotify_event*>(&buffer[0]);
                if (notifyEvent->len)
                {
                    if (watchFile == notifyEvent->name)
                    {
                        callback();
                    }
                }
            }
            else
            {
                log<level::ERR>("Failed to read inotify event");
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

} // namespace phosphor::certs
