#include "argument.hpp"

#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace phosphor::certs
{
namespace
{

TEST(ProcessArguments, OnSuccessClientType)
{
    Arguments arguments;
    std::vector<const char*> argv = {"binary",     "--type", "client",
                                     "--endpoint", "abc",    "--path",
                                     "def",        "--unit", "ghi"};
    EXPECT_EQ(processArguments(argv.size(), argv.data(), arguments), 0);
    EXPECT_EQ(arguments.typeStr, "client");
    EXPECT_EQ(arguments.endpoint, "abc");
    EXPECT_EQ(arguments.path, "def");
    EXPECT_EQ(arguments.unit, "ghi");
}

TEST(ProcessArguments, OnSuccessServerType)
{
    Arguments arguments;
    std::vector<const char*> argv = {"binary",     "--type", "server",
                                     "--endpoint", "abc",    "--path",
                                     "def",        "--unit", "ghi"};
    EXPECT_EQ(processArguments(argv.size(), argv.data(), arguments), 0);
    EXPECT_EQ(arguments.typeStr, "server");
    EXPECT_EQ(arguments.endpoint, "abc");
    EXPECT_EQ(arguments.path, "def");
    EXPECT_EQ(arguments.unit, "ghi");
}

TEST(ProcessArguments, OnSuccessAuthorityType)
{
    Arguments arguments;
    std::vector<const char*> argv = {"binary",     "--type", "authority",
                                     "--endpoint", "abc",    "--path",
                                     "def",        "--unit", "ghi"};
    EXPECT_NO_THROW(processArguments(argv.size(), argv.data(), arguments));
    EXPECT_EQ(arguments.typeStr, "authority");
    EXPECT_EQ(arguments.endpoint, "abc");
    EXPECT_EQ(arguments.path, "def");
    EXPECT_EQ(arguments.unit, "ghi");
}

TEST(ProcessArguments, UnitIsOptional)
{
    Arguments arguments;
    std::vector<const char*> argv = {"binary", "--type", "client", "--endpoint",
                                     "abc",    "--path", "def"};
    EXPECT_EQ(processArguments(argv.size(), argv.data(), arguments), 0);
    EXPECT_EQ(arguments.typeStr, "client");
    EXPECT_EQ(arguments.endpoint, "abc");
    EXPECT_EQ(arguments.path, "def");
    EXPECT_TRUE(arguments.unit.empty());
}

TEST(ProcessArguments, EmptyUnit)
{
    Arguments arguments;
    std::vector<const char*> argv = {"binary",     "--type", "client",
                                     "--endpoint", "abc",    "--path",
                                     "def",        "--unit", ""};
    EXPECT_EQ(processArguments(argv.size(), argv.data(), arguments), 0);
    EXPECT_EQ(arguments.typeStr, "client");
    EXPECT_EQ(arguments.endpoint, "abc");
    EXPECT_EQ(arguments.path, "def");
    EXPECT_TRUE(arguments.unit.empty());
}

TEST(Type, MissTypeThrows)
{
    Arguments arguments;
    std::vector<const char*> argv = {"binary", "--endpoint", "abc", "--path",
                                     "def",    "--unit",     "ghi"};
    EXPECT_NE(processArguments(argv.size(), argv.data(), arguments), 0);
}

TEST(Type, WrongTypeThrows)
{
    Arguments arguments;
    std::vector<const char*> argv = {"binary",     "--type", "no-supported",
                                     "--endpoint", "abc",    "--path",
                                     "def",        "--unit", "ghi"};
    EXPECT_NE(processArguments(argv.size(), argv.data(), arguments), 0);
}

TEST(Endpoint, MissEndpointThrows)
{
    Arguments arguments;
    std::vector<const char*> argv = {"binary", "--type", "client", "--path",
                                     "def",    "--unit", "ghi"};
    EXPECT_NE(processArguments(argv.size(), argv.data(), arguments), 0);
}

TEST(Path, MissPathThrows)
{
    Arguments arguments;
    std::vector<const char*> argv = {"binary", "--type", "client", "--endpoint",
                                     "abc",    "--unit", "ghi"};
    EXPECT_NE(processArguments(argv.size(), argv.data(), arguments), 0);
}
} // namespace

} // namespace phosphor::certs
