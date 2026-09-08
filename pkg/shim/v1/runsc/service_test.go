// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	apievents "github.com/containerd/containerd/api/events"
	task "github.com/containerd/containerd/api/runtime/task/v2"
	coreevents "github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
)

// errorPublisher is a publisher that always returns an error.
type errorPublisher struct{}

func (p *errorPublisher) Publish(_ context.Context, _ string, _ coreevents.Event) error {
	return fmt.Errorf("dial unix: missing address")
}

func (p *errorPublisher) Close() error { return nil }

// TestForwardDoesNotPanicOnPublishError verifies that the event forward
// function logs errors instead of panicking when the publisher fails and no
// event sink is configured (empty TTRPC_ADDRESS). This is how the shim runs
// under CRI-O, where publish errors are expected and non-fatal.
func TestForwardDoesNotPanicOnPublishError(t *testing.T) {
	// Empty TTRPC_ADDRESS means no event sink is configured (as under CRI-O).
	t.Setenv("TTRPC_ADDRESS", "")

	s := &runscService{
		events: make(chan any, 2),
	}
	s.events <- &apievents.TaskCreate{ContainerID: "test"}
	s.events <- &apievents.TaskExit{ContainerID: "test"}
	close(s.events)

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.forward(context.Background(), &errorPublisher{})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("forward did not complete within timeout")
	}
}

// TestForwardPanicsOnPublishErrorUnderContainerd verifies that, when a
// containerd event sink is configured (TTRPC_ADDRESS set), a publish failure
// remains fatal (panics) as it did before CRI-O support was added. This keeps
// the non-fatal behavior scoped to the CRI-O case only.
func TestForwardPanicsOnPublishErrorUnderContainerd(t *testing.T) {
	t.Setenv("TTRPC_ADDRESS", "/run/containerd/containerd.sock.ttrpc")

	s := &runscService{
		events: make(chan any, 1),
	}
	s.events <- &apievents.TaskCreate{ContainerID: "test"}
	close(s.events)

	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		s.forward(context.Background(), &errorPublisher{})
	}()

	select {
	case r := <-panicked:
		if r == nil {
			t.Fatal("forward did not panic on publish error under containerd")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forward did not complete within timeout")
	}
}

func TestContainerUpdateNilResources(t *testing.T) {
	c := &Container{}
	err := c.Update(t.Context(), &task.UpdateTaskRequest{ID: "x", Resources: nil})
	if !errors.Is(err, errdefs.ErrInvalidArgument) {
		t.Fatalf("Update(nil Resources): %v, want ErrInvalidArgument", err)
	}
}

func TestStripGVisorRestoreAnnotations(t *testing.T) {
	spec := &specs.Spec{
		Annotations: map[string]string{
			RestoreHostPathAnnotation:                  "/var/lib/criu-dumps/runsc-test",
			RestoreDirectAnnotation:                    "true",
			"dev.gvisor.internal.restore.extra":        "ignored",
			CheckpointSaveRestoreExecArgvAnnotation:    "/usr/local/bin/gvisor-cuda-hook",
			CheckpointSaveRestoreExecTimeoutAnnotation: "10m",
			utils.ContainerTypeAnnotation:              "sandbox",
			"dev.gvisor.keep":                          "yes",
			"example.com/annotation":                   "kept",
		},
	}

	stripGVisorRestoreAnnotations(spec)

	// restore.* annotations are shim-only and must be stripped.
	for _, key := range []string{
		RestoreHostPathAnnotation,
		RestoreDirectAnnotation,
		"dev.gvisor.internal.restore.extra",
	} {
		if _, ok := spec.Annotations[key]; ok {
			t.Errorf("stripGVisorRestoreAnnotations kept %q", key)
		}
	}
	// checkpoint.* (and everything else) must survive — the sentry consumes the
	// save-restore-exec annotations.
	for key, want := range map[string]string{
		CheckpointSaveRestoreExecArgvAnnotation:    "/usr/local/bin/gvisor-cuda-hook",
		CheckpointSaveRestoreExecTimeoutAnnotation: "10m",
		utils.ContainerTypeAnnotation:              "sandbox",
		"dev.gvisor.keep":                          "yes",
		"example.com/annotation":                   "kept",
	} {
		if got := spec.Annotations[key]; got != want {
			t.Errorf("stripGVisorRestoreAnnotations annotation %q = %q, want %q", key, got, want)
		}
	}
}

// TestFSRestoreFromSpec covers the gate that decides whether a pod's filesystem
// checkpoint is applied. The container case is the one that breaks a whole pod: CRI
// copies pod annotations onto every container's spec, and runsc rejects the flag for
// a container joining an existing sandbox.
func TestFSRestoreFromSpec(t *testing.T) {
	const image = "/var/lib/sandbox-snapshots/fs/abc"

	for _, tc := range []struct {
		name        string
		annotations map[string]string
		wantPath    string
		wantDirect  bool
		wantErr     bool
	}{
		{
			name: "pod sandbox restores",
			annotations: map[string]string{
				RestoreFSImagePathAnnotation:  image,
				RestoreFSDirectAnnotation:     "true",
				utils.ContainerTypeAnnotation: "sandbox",
			},
			wantPath:   image,
			wantDirect: true,
		},
		{
			name: "workload container does not",
			annotations: map[string]string{
				RestoreFSImagePathAnnotation:  image,
				utils.ContainerTypeAnnotation: "container",
			},
		},
		{
			name:        "no container type is its own sandbox",
			annotations: map[string]string{RestoreFSImagePathAnnotation: image},
			wantPath:    image,
		},
		{
			name: "direct defaults off",
			annotations: map[string]string{
				RestoreFSImagePathAnnotation:  image,
				RestoreFSDirectAnnotation:     "yes",
				utils.ContainerTypeAnnotation: "sandbox",
			},
			wantPath: image,
		},
		{
			name:        "direct alone does nothing",
			annotations: map[string]string{RestoreFSDirectAnnotation: "true"},
		},
		{
			name: "memory restore is mutually exclusive",
			annotations: map[string]string{
				RestoreFSImagePathAnnotation:  image,
				RestoreHostPathAnnotation:     "/var/lib/criu-dumps/x",
				utils.ContainerTypeAnnotation: "sandbox",
			},
			wantErr: true,
		},
		{name: "absent", annotations: map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, direct, err := fsRestoreFromSpec(&specs.Spec{Annotations: tc.annotations})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("fsRestoreFromSpec = (%q, %v, nil), want an error", path, direct)
				}
				if path != "" {
					t.Errorf("fsRestoreFromSpec returned path %q alongside an error", path)
				}
				return
			}
			if err != nil {
				t.Fatalf("fsRestoreFromSpec: %v", err)
			}
			if path != tc.wantPath {
				t.Errorf("path = %q, want %q", path, tc.wantPath)
			}
			if direct != tc.wantDirect {
				t.Errorf("direct = %v, want %v", direct, tc.wantDirect)
			}
		})
	}
}

// A nil spec is the read-failed path in CreateWithFSRestore, which must not panic.
func TestFSRestoreFromSpecNil(t *testing.T) {
	if path, direct, err := fsRestoreFromSpec(nil); path != "" || direct || err != nil {
		t.Errorf("fsRestoreFromSpec(nil) = (%q, %v, %v), want empty", path, direct, err)
	}
}

func TestCgroupPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{
			name: "simple",
			path: "foo/pod123/container",
			want: "foo/pod123",
		},
		{
			name: "absolute",
			path: "/foo/pod123/container",
			want: "/foo/pod123",
		},
		{
			name: "no-container",
			path: "foo/pod123",
			want: "",
		},
		{
			name: "no-container-absolute",
			path: "/foo/pod123",
			want: "",
		},
		{
			name: "double-pod",
			path: "/foo/podium/pod123/container",
			want: "/foo/podium/pod123",
		},
		{
			name: "start-pod",
			path: "pod123/container",
			want: "pod123",
		},
		{
			name: "start-pod-absolute",
			path: "/pod123/container",
			want: "/pod123",
		},
		{
			name: "slashes",
			path: "///foo/////pod123//////container",
			want: "/foo/pod123",
		},
		{
			name: "no-pod",
			path: "/foo/nopod123/container",
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := specs.Spec{
				Linux: &specs.Linux{
					CgroupsPath: tc.path,
				},
			}
			updated := setPodCgroup(&spec)
			if got := spec.Annotations[cgroupParentAnnotation]; got != tc.want {
				t.Errorf("setPodCgroup(%q), want: %q, got: %q", tc.path, tc.want, got)
			}
			if shouldUpdate := len(tc.want) > 0; shouldUpdate != updated {
				t.Errorf("setPodCgroup(%q)=%v, want: %v", tc.path, updated, shouldUpdate)
			}
		})
	}
}

// Test cases that cgroup path should not be updated.
func TestCgroupNoUpdate(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec *specs.Spec
	}{
		{
			name: "empty",
			spec: &specs.Spec{},
		},
		{
			name: "subcontainer",
			spec: &specs.Spec{
				Linux: &specs.Linux{
					CgroupsPath: "foo/pod123/container",
				},
				Annotations: map[string]string{
					utils.ContainerTypeAnnotation: utils.ContainerTypeContainer,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if updated := setPodCgroup(tc.spec); updated {
				t.Errorf("setPodCgroup(%+v), got: %v, want: false", tc.spec.Linux, updated)
			}
		})
	}
}
