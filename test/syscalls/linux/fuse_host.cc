// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Tests for FUSE host passthrough: a FUSE filesystem served by a host-side
// FUSE server communicating over a socketpair.
//
// These tests are run with the _fuse_host suffix. The test runner starts a
// host FUSE server, passes the socketpair FD into the sandbox, and sets
// GVISOR_FUSE_HOST_TEST=TRUE and GVISOR_FUSE_HOST_FD=<fd>.

#include <fcntl.h>
#include <linux/capability.h>
#include <linux/fuse.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "test/util/file_descriptor.h"
#include "test/util/fs_util.h"
#include "test/util/linux_capability_util.h"
#include "test/util/mount_util.h"
#include "test/util/posix_error.h"
#include "test/util/temp_path.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

// Returns the FD number for the host FUSE socketpair end, or -1 if not set.
int GetFuseHostFD() {
  const char* fd_str = getenv("GVISOR_FUSE_HOST_FD");
  if (fd_str == nullptr) return -1;
  return atoi(fd_str);
}

// FuseHostTest exercises the FUSE host passthrough path by mounting a FUSE
// filesystem using a host FD (socketpair end) and performing file operations.
class FuseHostTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SKIP_IF(absl::NullSafeStringView(getenv("GVISOR_FUSE_HOST_TEST")) !=
            "TRUE");
    SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_SYS_ADMIN)));

    fuse_fd_ = GetFuseHostFD();
    ASSERT_GE(fuse_fd_, 0) << "GVISOR_FUSE_HOST_FD not set";

    mount_point_ = ASSERT_NO_ERRNO_AND_VALUE(TempPath::CreateDir());
    auto mount_opts = absl::StrFormat(
        "fd=%d,user_id=0,group_id=0,rootmode=40000", fuse_fd_);
    mount_ = ASSERT_NO_ERRNO_AND_VALUE(
        Mount("fuse", mount_point_.path(), "fuse", MS_NODEV | MS_NOSUID,
              mount_opts, 0));
  }

  int fuse_fd_ = -1;
  TempPath mount_point_;
  Cleanup mount_;
};

TEST_F(FuseHostTest, StatRoot) {
  struct stat st;
  ASSERT_THAT(stat(mount_point_.path().c_str(), &st), SyscallSucceeds());
  EXPECT_TRUE(S_ISDIR(st.st_mode));
}

TEST_F(FuseHostTest, ReadFile) {
  const std::string expected = "hello from the host FUSE server\n";
  const std::string path =
      JoinPath(mount_point_.path(), "testfile");

  FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDONLY));
  std::vector<char> buf(expected.size());
  ASSERT_THAT(ReadFd(fd.get(), buf.data(), expected.size()),
              SyscallSucceedsWithValue(expected.size()));
  EXPECT_EQ(std::string(buf.data(), buf.size()), expected);
}

TEST_F(FuseHostTest, WriteAndReadBack) {
  const std::string path =
      JoinPath(mount_point_.path(), "testfile");

  // Write new data.
  const std::string write_data = "overwritten by test\n";
  {
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_WRONLY));
    ASSERT_THAT(WriteFd(fd.get(), write_data.data(), write_data.size()),
                SyscallSucceedsWithValue(write_data.size()));
  }

  // Read it back.
  {
    FileDescriptor fd = ASSERT_NO_ERRNO_AND_VALUE(Open(path, O_RDONLY));
    std::vector<char> buf(write_data.size());
    ASSERT_THAT(ReadFd(fd.get(), buf.data(), write_data.size()),
                SyscallSucceedsWithValue(write_data.size()));
    EXPECT_EQ(std::string(buf.data(), buf.size()), write_data);
  }
}

}  // namespace
}  // namespace testing
}  // namespace gvisor
