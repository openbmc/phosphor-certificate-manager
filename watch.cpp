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

    timerPtr = std::make_unique<Timer>(event, [this](Timer&) { callback(); });
}

Watch::~Watch()
{
    stopWatch();
}

void Watch::startWatch()
{
    log<level::INFO>("Watch: Start watch");
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
            std::array<char, 4096> buffer;
            ssize_t length = read(fd, buffer.data(), buffer.size());
            int i = 0;
            while (i < length)
            {
                struct inotify_event* notifyEvent =
                    reinterpret_cast<struct inotify_event*>(&buffer[i]);
                if (notifyEvent->len)
                {
                    log<level::INFO>("Watch file name received is",
                                     entry("FILE_NAME=%s", notifyEvent->name));
                    if (watchFile == notifyEvent->name)
                    {
                        // after notification it takes a while for the file
                        // to have data, start timer for 3 seconds and then
                        // read data
                        std::chrono::seconds delay(3);
                        timerPtr->restartOnce(delay);
                    }
                }
                i += (sizeof(struct inotify_event)) + notifyEvent->len;
            }
        });
}

void Watch::stopWatch()
{
    log<level::INFO>("Watch: stop watch");
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
