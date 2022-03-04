#!/bin/bash
set -e
app_binary=${APP_BINARY:="./build/phosphor-certificate-manager"}

function EXPECT_SUCCESS() {
  local cmd="$@"
  ${cmd} || (echo "test failed; expect $cmd to be successful" && exit 1)
}

function EXPECT_FAILURE() {
  local cmd="$@"
  ${cmd} || (exit 0)
}

#################
# Expect Success
#################
EXPECT_SUCCESS ${app_binary} --type client --endpoint abc --path abc --unit abc --dry-run
EXPECT_SUCCESS ${app_binary} --type server --endpoint abc --path abc --unit abc --dry-run
EXPECT_SUCCESS ${app_binary} --type authority --endpoint abc --path abc --unit abc --dry-run
# unit is optional
EXPECT_SUCCESS ${app_binary} --type authority --endpoint abc --path abc --dry-run

#################
# EXPECT Failure
#################
# miss type
EXPECT_FAILURE ${app_binary} --endpoint abc  --path abc --unit abc --dry-run
# wrong type
EXPECT_FAILURE ${app_binary} --type wrong --endpoint abc --path abc --unit abc --dry-run
# miss endpoint
EXPECT_FAILURE ${app_binary} --type client  --path abc --unit abc --dry-run
# miss path
EXPECT_FAILURE ${app_binary} --type client --endpoint abc --unit abc --dry-run
