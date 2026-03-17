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

TEST_F(TestWatch, WatchWithNonExistentFile)
{
    std::string nonExistentFile = testDir + "/nonexistent.pem";
    auto callback = []() { incrementCallbackCount(); };

    EXPECT_NO_THROW({ Watch watch(event, nonExistentFile, callback); });
}

TEST_F(TestWatch, WatchWithDirectoryPath)
{
    auto callback = []() { incrementCallbackCount(); };

    EXPECT_NO_THROW({ Watch watch(event, testDir, callback); });
}

TEST_F(TestWatch, WatchWithLongFilePath)
{
    std::string longPath = testDir + "/" + std::string(200, 'a') + ".pem";
    createTestFile(longPath, "test content");
    auto callback = []() { incrementCallbackCount(); };

    EXPECT_NO_THROW({ Watch watch(event, longPath, callback); });
}

TEST_F(TestWatch, WatchWithSpecialCharactersInPath)
{
    std::string specialPath = testDir + "/test-cert_file.pem";
    createTestFile(specialPath, "test content");
    auto callback = []() { incrementCallbackCount(); };

    EXPECT_NO_THROW({ Watch watch(event, specialPath, callback); });
}

TEST_F(TestWatch, MultipleWatchesOnSameFile)
{
    auto callback1 = []() { incrementCallbackCount(); };
    auto callback2 = []() { incrementCallbackCount(); };

    EXPECT_NO_THROW({
        Watch watch1(event, testCertFile, callback1);
        Watch watch2(event, testCertFile, callback2);
    });
}

TEST_F(TestWatch, MultipleWatchesOnDifferentFiles)
{
    std::string file1 = testDir + "/cert1.pem";
    std::string file2 = testDir + "/cert2.pem";
    createTestFile(file1, "content1");
    createTestFile(file2, "content2");

    auto callback1 = []() { incrementCallbackCount(); };
    auto callback2 = []() { incrementCallbackCount(); };

    EXPECT_NO_THROW({
        Watch watch1(event, file1, callback1);
        Watch watch2(event, file2, callback2);
    });
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

TEST_F(TestWatch, WatchWithThrowingCallback)
{
    auto throwingCallback = []() {
        throw std::runtime_error("Callback exception");
    };

    EXPECT_NO_THROW({ Watch watch(event, testCertFile, throwingCallback); });
}

TEST_F(TestWatch, WatchWithRelativeFilePath)
{
    std::string relativePath = "./test.pem";
    auto callback = []() { incrementCallbackCount(); };

    EXPECT_NO_THROW({ Watch watch(event, relativePath, callback); });
}

TEST_F(TestWatch, WatchWithAbsoluteFilePath)
{
    auto callback = []() { incrementCallbackCount(); };

    EXPECT_NO_THROW({ Watch watch(event, testCertFile, callback); });
}

TEST_F(TestWatch, WatchWithNestedDirectory)
{
    std::string nestedDir = testDir + "/nested/dir";
    fs::create_directories(nestedDir);
    std::string nestedFile = nestedDir + "/cert.pem";
    createTestFile(nestedFile, "nested content");

    auto callback = []() { incrementCallbackCount(); };

    EXPECT_NO_THROW({ Watch watch(event, nestedFile, callback); });
}

TEST_F(TestWatch, WatchWithNoExtension)
{
    std::string noExtFile = testDir + "/certfile";
    createTestFile(noExtFile, "no extension");
    auto callback = []() { incrementCallbackCount(); };

    EXPECT_NO_THROW({ Watch watch(event, noExtFile, callback); });
}

TEST_F(TestWatch, WatchWithMultipleExtensions)
{
    std::string multiExtFile = testDir + "/cert.pem.backup.old";
    createTestFile(multiExtFile, "multiple extensions");
    auto callback = []() { incrementCallbackCount(); };

    EXPECT_NO_THROW({ Watch watch(event, multiExtFile, callback); });
}

TEST_F(TestWatch, WatchWithDifferentEventObjects)
{
    sdeventplus::Event event1 = sdeventplus::Event::get_default();
    sdeventplus::Event event2 = sdeventplus::Event::get_new();

    auto callback = []() { incrementCallbackCount(); };

    EXPECT_NO_THROW({
        Watch watch1(event1, testCertFile, callback);
        Watch watch2(event2, testCertFile, callback);
    });
}

} // namespace
} // namespace phosphor::certs
