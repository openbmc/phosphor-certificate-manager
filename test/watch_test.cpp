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
    TestWatch() : event(sdeventplus::Event::get_default()) {}

    void SetUp() override
    {
        char dirTemplate[] = "/tmp/WatchTest.XXXXXX";
        auto dirPtr = mkdtemp(dirTemplate);
        ASSERT_NE(dirPtr, nullptr) << "Failed to create temp directory";
        testDir = dirPtr;
        testCertFile = testDir + "/test.pem";

        std::ofstream file(testCertFile);
        ASSERT_TRUE(file) << "Failed to create test file";
        file << "Initial content";
        file.close();
    }

    void TearDown() override
    {
        fs::remove_all(testDir);
    }

  protected:
    sdeventplus::Event event;
    std::string testDir;
    std::string testCertFile;
};

TEST_F(TestWatch, CreateWatchWithValidParameters)
{
    auto callback = []() {};
    EXPECT_NO_THROW({ Watch watch(event, testCertFile, callback); });
}

TEST_F(TestWatch, StartWatch)
{
    auto callback = []() {};
    Watch watch(event, testCertFile, callback);
    EXPECT_NO_THROW(watch.startWatch());
}

TEST_F(TestWatch, StopWatch)
{
    auto callback = []() {};
    Watch watch(event, testCertFile, callback);
    EXPECT_NO_THROW(watch.stopWatch());
}

TEST_F(TestWatch, StartWatchAfterStop)
{
    auto callback = []() {};
    Watch watch(event, testCertFile, callback);
    watch.stopWatch();
    EXPECT_NO_THROW(watch.startWatch());
}

TEST_F(TestWatch, StopWatchMultipleTimes)
{
    auto callback = []() {};
    Watch watch(event, testCertFile, callback);
    EXPECT_NO_THROW(watch.stopWatch());
    EXPECT_NO_THROW(watch.stopWatch());
}

} // namespace
} // namespace phosphor::certs
