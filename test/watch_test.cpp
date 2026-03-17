#include "config.h"

#include "watch.hpp"

#include <sdeventplus/event.hpp>
#include <sdeventplus/test/sdevent.hpp>

#include <filesystem>
#include <fstream>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace phosphor::certs
{
namespace
{
namespace fs = std::filesystem;

class TestWatch : public ::testing::Test
{
  public:
    TestWatch() : event(sdeventplus::Event::get_default())
    {
        callbackCount = 0;
    }

    void SetUp() override
    {
        char dirTemplate[] = "/tmp/WatchTest.XXXXXX";
        auto dirPtr = mkdtemp(dirTemplate);
        if (dirPtr == nullptr)
        {
            throw std::runtime_error("Failed to create temp directory");
        }
        testDir = dirPtr;

        testCertFile = testDir + "/test.pem";
        createTestFile(testCertFile, "Initial content");
    }

    void TearDown() override
    {
        if (fs::exists(testDir))
        {
            fs::remove_all(testDir);
        }
    }

    void createTestFile(const std::string& path, const std::string& content)
    {
        std::ofstream file(path);
        file << content;
        file.close();
    }

    void modifyTestFile(const std::string& path, const std::string& content)
    {
        std::ofstream file(path, std::ios::trunc);
        file << content;
        file.close();
    }

    void deleteTestFile(const std::string& path)
    {
        if (fs::exists(path))
        {
            fs::remove(path);
        }
    }

    static void incrementCallbackCount()
    {
        callbackCount++;
    }

    static void resetCallbackCount()
    {
        callbackCount = 0;
    }

    static int getCallbackCount()
    {
        return callbackCount;
    }

  protected:
    sdeventplus::Event event;
    std::string testDir;
    std::string testCertFile;
    static int callbackCount;
};

int TestWatch::callbackCount = 0;

TEST_F(TestWatch, CreateWatchWithValidParameters)
{
    auto callback = []() { TestWatch::incrementCallbackCount(); };

    EXPECT_NO_THROW({ Watch watch(event, testCertFile, callback); });
}

TEST_F(TestWatch, StartWatchExplicitly)
{
    auto callback = []() { incrementCallbackCount(); };
    Watch watch(event, testCertFile, callback);

    EXPECT_NO_THROW(watch.startWatch());
}

TEST_F(TestWatch, StopWatch)
{
    auto callback = []() { incrementCallbackCount(); };
    Watch watch(event, testCertFile, callback);

    EXPECT_NO_THROW(watch.stopWatch());
}

TEST_F(TestWatch, StartStopWatchMultipleTimes)
{
    auto callback = []() { incrementCallbackCount(); };
    Watch watch(event, testCertFile, callback);

    for (int i = 0; i < 5; ++i)
    {
        EXPECT_NO_THROW(watch.stopWatch());
        EXPECT_NO_THROW(watch.startWatch());
    }
}

TEST_F(TestWatch, WatchWithDirectoryPath)
{
    auto callback = []() { incrementCallbackCount(); };

    EXPECT_NO_THROW({ Watch watch(event, testDir, callback); });
}

TEST_F(TestWatch, StartWatchAfterStop)
{
    auto callback = []() { incrementCallbackCount(); };
    Watch watch(event, testCertFile, callback);

    watch.stopWatch();
    EXPECT_NO_THROW(watch.startWatch());
}

TEST_F(TestWatch, MultipleStartCallsWithoutStop)
{
    auto callback = []() { incrementCallbackCount(); };
    Watch watch(event, testCertFile, callback);

    EXPECT_NO_THROW(watch.startWatch());
    EXPECT_NO_THROW(watch.startWatch());
    EXPECT_NO_THROW(watch.startWatch());
}

TEST_F(TestWatch, MultipleStopCallsWithoutStart)
{
    auto callback = []() { incrementCallbackCount(); };
    Watch watch(event, testCertFile, callback);

    EXPECT_NO_THROW(watch.stopWatch());
    EXPECT_NO_THROW(watch.stopWatch());
    EXPECT_NO_THROW(watch.stopWatch());
}

TEST_F(TestWatch, WatchWithEmptyCallback)
{
    auto emptyCallback = []() {};

    EXPECT_NO_THROW({ Watch watch(event, testCertFile, emptyCallback); });
}

} // namespace
} // namespace phosphor::certs
