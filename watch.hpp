#pragma once

#include <memory>
#include <sdeventplus/source/event.hpp>
#include <sdeventplus/source/io.hpp>
#include <sdeventplus/utility/timer.hpp>
namespace phosphor
{
namespace certs
{
constexpr auto clockId = sdeventplus::ClockId::RealTime;
/** @class Watch
 *
 *  @brief Adds inotify watch on certificate file added/replaced
 *
 *  The inotify watch is hooked up with sd-event, so that on callback,
 *  appropriate actions related to a certificate upload/replace can be taken.
 */
class Watch
{
  public:
    using Callback = std::function<void()>;
    using Timer = sdeventplus::utility::Timer<clockId>;
    /** @brief ctor - hook inotify watch with sd-event
     *
     *  @param[in] event - sd-event object
     *  @param[in] watch - path to watch
     *  @param[in] certFile - path to the certificate file
     *  @param[in] mask - events to be monitored for the path
     *  @param[in] cb - The callback function for processing
     *                             certificate upload/replace
     */
    Watch(sdeventplus::Event& event, const std::string& watch,
          const std::string& certFile, uint32_t mask, Callback cb);

    Watch(const Watch&) = delete;
    Watch& operator=(const Watch&) = delete;
    Watch(Watch&&) = delete;
    Watch& operator=(Watch&&) = delete;

    /** @brief dtor - remove inotify watch and close fd's
     */
    ~Watch();

    /** @brief start watch on the specified path
     */
    void startWatch();

    /** @brief stop watch on the specified path
     */
    void stopWatch();

  private:
    /** @brief Read ceritificate file and update D-Bus certificate properties
     */
    void readCertificate();

    /** @brief certificate upload directory/file watch descriptor */
    int wd = -1;

    /** @brief inotify file descriptor */
    int fd = -1;

    /** @brief SDEventPlus IO pointer added to event loop */
    std::unique_ptr<sdeventplus::source::IO> ioPtr = nullptr;

    /** @brief sd-event object */
    sdeventplus::Event& event;

    /** @brief certificate directory/file to watch */
    std::string watch;

    /** @brief certificate file uploaded/replaced */
    std::string certFile;

    /** @brief events to be monitored for the path*/
    uint32_t mask;

    /** @brief callback method to be called for upload/replace*/
    Callback callback;

    /** @brief Timer to read the certificate file after some duration*/
    std::unique_ptr<Timer> timerPtr = nullptr;
};
} // namespace certs
} // namespace phosphor
