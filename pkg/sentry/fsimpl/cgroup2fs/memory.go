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

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// +stateify savable
type memory struct {
	c      *cgroup
	parent *memory
	id     uint32
}

func (c *memory) canEnter(ctx context.Context, t *kernel.Task) bool { return true }
func (c *memory) cancelEnter(ctx context.Context, t *kernel.Task)   {}

func (c *memory) enter(ctx context.Context, t *kernel.Task) {
	t.SetMemCgID(c.id)
}

func (c *memory) exit(ctx context.Context, t *kernel.Task) {
	t.SetMemCgID(0)
}

func (c *memory) canAttach(ctx context.Context, actx *attachCtx) bool { return true }
func (c *memory) cancelAttach(ctx context.Context, actx *attachCtx)   {}

func (c *memory) attach(ctx context.Context, actx *attachCtx) {
	for t := range actx.tasks {
		t.SetMemCgID(c.id)
	}
}

func (c *memory) interfaceFiles() []interfaceFile {
	return []interfaceFile{
		{name: "memory.events", source: &memoryEvents{}, perm: 0444},
		{name: "memory.current", source: &memoryCurrent{c: c}, perm: 0444},
		{name: "memory.max", source: &memoryMax{}, perm: 0644},
		{name: "memory.high", source: &memoryHigh{}, perm: 0644},
	}
}

func (c *memory) interfaceFileNames() []string {
	return []string{"memory.events", "memory.current", "memory.max", "memory.high"}
}

// +stateify savable
type memoryEvents struct{}

// Generate implements vfs.DynamicBytesSource.Generate.
func (m *memoryEvents) Generate(ctx context.Context, buf *bytes.Buffer) error {
	buf.WriteString("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
	return nil
}

// v1 equivalent memory.usage_in_bytes is not a stub.
// +stateify savable
type memoryCurrent struct {
	c *memory
}

// Collects all the memory cgroup ids for the cgroup.
// +checklocksread:c.fs.treeMu
func (m *memoryCurrent) collectMemCgIDs(c *cgroup, memCgIDs map[uint32]struct{}) {
	// Add ourselves.
	if mem := c.ctrls[kernel.Cgroup2Memory]; mem != nil {
		memCgIDs[mem.(*memory).id] = struct{}{}
	}
	// Add our children.
	for child := range c.children {
		m.collectMemCgIDs(child, memCgIDs) // +checklocksforce: c.fs.treeMu is locked
	}
}

// Returns the memory usage for all cgroup ids in memCgIDs.
func getUsage(k *kernel.Kernel, memCgIDs map[uint32]struct{}) uint64 {
	k.MemoryFile().UpdateUsage(memCgIDs)
	var totalBytes uint64
	for id := range memCgIDs {
		_, bytes := usage.MemoryAccounting.CopyPerCg(id)
		totalBytes += bytes
	}
	return totalBytes
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (m *memoryCurrent) Generate(ctx context.Context, buf *bytes.Buffer) error {
	k := kernel.KernelFromContext(ctx)

	memCgIDs := make(map[uint32]struct{})
	m.c.c.fs.treeMu.RLock()
	m.collectMemCgIDs(m.c.c, memCgIDs)
	m.c.c.fs.treeMu.RUnlock()

	totalBytes := getUsage(k, memCgIDs)
	fmt.Fprintf(buf, "%d\n", totalBytes)
	return nil
}

// +stateify savable
type memoryMax struct{}

// Generate implements vfs.DynamicBytesSource.Generate.
func (m *memoryMax) Generate(ctx context.Context, buf *bytes.Buffer) error {
	buf.WriteString("max\n")
	return nil
}

// +stateify savable
type memoryHigh struct{}

// Generate implements vfs.DynamicBytesSource.Generate.
func (m *memoryHigh) Generate(ctx context.Context, buf *bytes.Buffer) error {
	buf.WriteString("max\n")
	return nil
}
