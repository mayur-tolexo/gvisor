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

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// +stateify savable
type cpu struct {
	c      *cgroup
	parent *cpu
}

func (c *cpu) canEnter(ctx context.Context, t *kernel.Task) bool   { return true }
func (c *cpu) cancelEnter(ctx context.Context, t *kernel.Task)     {}
func (c *cpu) enter(ctx context.Context, t *kernel.Task)           {}
func (c *cpu) exit(ctx context.Context, t *kernel.Task)            {}
func (c *cpu) canAttach(ctx context.Context, actx *attachCtx) bool { return true }
func (c *cpu) cancelAttach(ctx context.Context, actx *attachCtx)   {}
func (c *cpu) attach(ctx context.Context, actx *attachCtx)         {}
func (c *cpu) interfaceFiles() []interfaceFile {
	return []interfaceFile{
		{name: "cpu.stat", source: &cpuStat{}, perm: 0444, showAtRoot: true},
		{name: "cpu.max", source: &cpuMax{}, perm: 0644},
		{name: "cpu.weight", source: &cpuWeight{}, perm: 0644},
	}
}
func (c *cpu) interfaceFileNames() []string {
	return []string{"cpu.stat", "cpu.max", "cpu.weight"}
}

// +stateify savable
type cpuStat struct{}

// Generate implements vfs.DynamicBytesSource.Generate.
func (c *cpuStat) Generate(ctx context.Context, buf *bytes.Buffer) error {
	buf.WriteString("usage_usec 0\nuser_usec 0\nsystem_usec 0\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\n")
	return nil
}

// +stateify savable
type cpuMax struct{}

// Generate implements vfs.DynamicBytesSource.Generate.
func (c *cpuMax) Generate(ctx context.Context, buf *bytes.Buffer) error {
	buf.WriteString("max 100000\n")
	return nil
}

// +stateify savable
type cpuWeight struct{}

// Generate implements vfs.DynamicBytesSource.Generate.
func (c *cpuWeight) Generate(ctx context.Context, buf *bytes.Buffer) error {
	buf.WriteString("100\n")
	return nil
}
