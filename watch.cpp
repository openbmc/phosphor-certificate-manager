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

Watch::Watch(sdeventplus::Event& event, const std::string& watch,
             const std::string& certFile, uint32_t mask, Callback cb) :
    event(event),
    watch(watch), certFile(certFile), mask(mask), callback(cb)
{
    log<level::INFO>("Adding watch ", entry("WATCH=%s", watch.c_str()),
                     entry("CERT_FIE=%s", certFile.c_str()));
    startWatch();

    timerPtr = std::make_unique<Timer>(
        event, [this](Timer&) { this->readCertificate(); });
}

Watch::~Watch()
{
    stopWatch();
}

void Watch::readCertificate()
{
    log<level::INFO>("Watch readCertificate");
    std::error_code ec; // use non throwing file_size method
    if (fs::exists(certFile) && fs::file_size(certFile, ec) > 0)
    {
        log<level::INFO>("Watch file exists and has data initiate callback");
        callback();
    }
    else
    {
        log<level::INFO>("Watch file does not exist",
                         entry("FILE_NAME=%s", certFile.c_str()));
    }
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
            log<level::INFO>("Watch received inotify notification ");
            // check if expected event is received
            std::array<char, 4096> buffer;
            ssize_t bytes = read(fd, buffer.data(), buffer.size());
            if (bytes > 0)
            {
                int i = 0;
                struct inotify_event* notifyEvent =
                    reinterpret_cast<struct inotify_event*>(&buffer[i]);
                if (notifyEvent->len)
                {
                    std::string certFileName = fs::path(certFile).filename();
                    if (certFileName == notifyEvent->name)
                    {
                        // after notification it takes a while for the file
                        // to have data, start timer for 3 seconds and then
                        // read data
                        std::chrono::seconds delay(3);
                        timerPtr->restartOnce(delay);
                    }
                }
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
