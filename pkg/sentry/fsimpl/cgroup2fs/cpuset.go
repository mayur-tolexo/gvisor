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

package cgroup2fs

import (
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// +stateify savable
type cpuset struct {
	c      *cgroup
	parent *cpuset

	mu sync.Mutex `state:"nosave"`

	cpus *bitmap.Bitmap
	mems *bitmap.Bitmap
}

func (c *cpuset) canEnter(ctx context.Context, t *kernel.Task) bool   { return true }
func (c *cpuset) cancelEnter(ctx context.Context, t *kernel.Task)     {}
func (c *cpuset) enter(ctx context.Context, t *kernel.Task)           {}
func (c *cpuset) exit(ctx context.Context, t *kernel.Task)            {}
func (c *cpuset) canAttach(ctx context.Context, actx *attachCtx) bool { return true }
func (c *cpuset) cancelAttach(ctx context.Context, actx *attachCtx)   {}
func (c *cpuset) attach(ctx context.Context, actx *attachCtx)         {}
func (c *cpuset) interfaceFiles() []interfaceFile {
	return []interfaceFile{
		{name: "cpuset.cpus", source: &cpusetCpus{c: c}, perm: 0644},
		{name: "cpuset.mems", source: &cpusetMems{c: c}, perm: 0644},
	}
}
func (c *cpuset) interfaceFileNames() []string {
	return []string{"cpuset.cpus", "cpuset.mems"}
}

// +stateify savable
type cpusetCpus struct {
	c *cpuset
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *cpusetCpus) Generate(ctx context.Context, buf *bytes.Buffer) error {
	d.c.mu.Lock()
	defer d.c.mu.Unlock()
	if d.c.cpus != nil {
		fmt.Fprintf(buf, "%s\n", bitmap.FormatList(d.c.cpus))
	} else {
		buf.WriteString("\n")
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *cpusetCpus) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if src.NumBytes() > hostarch.PageSize {
		return 0, linuxerr.EINVAL
	}

	k := kernel.KernelFromContext(ctx)
	if k == nil {
		return 0, linuxerr.EINVAL
	}
	maxCpus := uint32(k.ApplicationCores())

	buf := make([]byte, src.NumBytes())
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, err
	}
	buf = buf[:n]

	b, err := bitmap.ParseList(string(buf), maxCpus)
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	if got, want := b.Maximum(), maxCpus; got > want {
		return 0, linuxerr.EINVAL
	}

	d.c.mu.Lock()
	defer d.c.mu.Unlock()
	d.c.cpus = b
	return int64(n), nil
}

// +stateify savable
type cpusetMems struct {
	c *cpuset
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *cpusetMems) Generate(ctx context.Context, buf *bytes.Buffer) error {
	d.c.mu.Lock()
	defer d.c.mu.Unlock()
	if d.c.mems != nil {
		fmt.Fprintf(buf, "%s\n", bitmap.FormatList(d.c.mems))
	} else {
		buf.WriteString("\n")
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *cpusetMems) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if src.NumBytes() > hostarch.PageSize {
		return 0, linuxerr.EINVAL
	}

	maxMems := uint32(1)

	buf := make([]byte, src.NumBytes())
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, err
	}
	buf = buf[:n]

	b, err := bitmap.ParseList(string(buf), maxMems)
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	if got, want := b.Maximum(), maxMems; got > want {
		return 0, linuxerr.EINVAL
	}

	d.c.mu.Lock()
	defer d.c.mu.Unlock()
	d.c.mems = b
	return int64(n), nil
}
