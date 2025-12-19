// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2025 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package snapstate

import (
	"fmt"
	"strings"
	"testing"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/snap"
)

func taskTestID(t *state.Task) (string, error) {
	var id string
	if err := t.Get("test-id", &id); err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("empty test-id")
	}
	return id, nil
}

func buildAdjacencyByTestID(t *testing.T, tasks map[string]*state.Task) map[string][]string {
	t.Helper()
	adj := make(map[string][]string, len(tasks))
	for id := range tasks {
		adj[id] = nil
	}
	for _, tsk := range tasks {
		to, err := taskTestID(tsk)
		if err != nil {
			t.Fatal(err)
		}
		for _, prereq := range tsk.WaitTasks() {
			from, err := taskTestID(prereq)
			if err != nil {
				t.Fatal(err)
			}
			adj[from] = append(adj[from], to)
		}
	}
	return adj
}

func computeReachability(ids []string, adj map[string][]string) map[string]map[string]bool {
	reach := make(map[string]map[string]bool, len(ids))
	for _, src := range ids {
		seen := make(map[string]bool, len(ids))
		queue := []string{src}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, next := range adj[cur] {
				if seen[next] {
					continue
				}
				seen[next] = true
				queue = append(queue, next)
			}
		}
		reach[src] = seen
	}
	return reach
}

func mkSnapSetupForArrangeEquivalenceTest(snapName string, snapType snap.Type, base string) *SnapSetup {
	return &SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: snapName,
			SnapID:   snapName,
			Revision: snap.R(1),
		},
		Type: snapType,
		Base: base,
	}
}

func mkOldTaskSetForArrangeEquivalenceTest(st *state.State, snapName string, snapType snap.Type, base string) (*state.TaskSet, map[string]*state.Task) {
	snapsup := mkSnapSetupForArrangeEquivalenceTest(snapName, snapType, base)

	download := st.NewTask("download-snap", "...")
	download.Set("snap-setup", snapsup)
	download.Set("test-id", snapName+":download")

	unlink := st.NewTask("unlink-snap", "...")
	unlink.WaitFor(download)
	unlink.Set("test-id", snapName+":unlink")

	link := st.NewTask("link-snap", "...")
	link.WaitFor(unlink)
	link.Set("test-id", snapName+":link")

	autoConnect := st.NewTask("auto-connect", "...")
	autoConnect.WaitFor(link)
	autoConnect.Set("test-id", snapName+":auto")

	ts := state.NewTaskSet(download, unlink, link, autoConnect)
	ts.MarkEdge(download, BeginEdge)
	ts.MarkEdge(link, MaybeRebootEdge)
	ts.MarkEdge(autoConnect, MaybeRebootWaitEdge)
	ts.MarkEdge(autoConnect, EndEdge)

	return ts, map[string]*state.Task{
		snapName + ":download": download,
		snapName + ":unlink":   unlink,
		snapName + ":link":     link,
		snapName + ":auto":     autoConnect,
	}
}

func mkInstallTaskSetForArrangeEquivalenceTest(st *state.State, snapName string, snapType snap.Type, base string) (snapInstallTaskSet, map[string]*state.Task) {
	snapsup := mkSnapSetupForArrangeEquivalenceTest(snapName, snapType, base)

	download := st.NewTask("download-snap", "...")
	download.Set("snap-setup", snapsup)
	download.Set("test-id", snapName+":download")

	unlink := st.NewTask("unlink-snap", "...")
	unlink.WaitFor(download)
	unlink.Set("test-id", snapName+":unlink")

	link := st.NewTask("link-snap", "...")
	link.WaitFor(unlink)
	link.Set("test-id", snapName+":link")

	autoConnect := st.NewTask("auto-connect", "...")
	autoConnect.WaitFor(link)
	autoConnect.Set("test-id", snapName+":auto")

	sts := snapInstallTaskSet{
		snapsup: *snapsup,

		beforeLocalSystemModificationsTasks: []*state.Task{download},
		beforeReboot:                        []*state.Task{unlink, link},
		postReboot:                          []*state.Task{autoConnect},
	}

	return sts, map[string]*state.Task{
		snapName + ":download": download,
		snapName + ":unlink":   unlink,
		snapName + ":link":     link,
		snapName + ":auto":     autoConnect,
	}
}

func TestArrangeImplementationOnlyDiffersInDownloadParallelization(t *testing.T) {
	dirs.SetRootDir(t.TempDir())
	defer dirs.SetRootDir("")

	model := modelBaseCore20ForLaneMergeTest()
	oldDeviceCtx := DeviceCtx
	DeviceCtx = func(st *state.State, task *state.Task, providedDeviceCtx DeviceContext) (DeviceContext, error) {
		if providedDeviceCtx != nil {
			return providedDeviceCtx, nil
		}
		return &trivialDeviceContextForLaneMergeTest{model: model}, nil
	}
	defer func() { DeviceCtx = oldDeviceCtx }()

	// Build equivalent graphs in separate states.
	stOld := state.New(nil)
	stNew := state.New(nil)

	stOld.Lock()
	defer stOld.Unlock()
	stNew.Lock()
	defer stNew.Unlock()

	snaps := []struct {
		name  string
		type_ snap.Type
		base  string
	}{
		{name: "snapd", type_: snap.TypeSnapd, base: ""},
		{name: "core20", type_: snap.TypeBase, base: "core20"},
		{name: "brand-gadget", type_: snap.TypeGadget, base: "core20"},
		{name: "kernel", type_: snap.TypeKernel, base: "core20"},
		{name: "my-app", type_: snap.TypeApp, base: "core20"},
	}

	var oldTaskSets []*state.TaskSet
	var newTaskSets []snapInstallTaskSet
	oldTasks := make(map[string]*state.Task)
	newTasks := make(map[string]*state.Task)

	for _, s := range snaps {
		ts, tasks := mkOldTaskSetForArrangeEquivalenceTest(stOld, s.name, s.type_, s.base)
		oldTaskSets = append(oldTaskSets, ts)
		for id, tsk := range tasks {
			oldTasks[id] = tsk
		}

		sts, tasks2 := mkInstallTaskSetForArrangeEquivalenceTest(stNew, s.name, s.type_, s.base)
		newTaskSets = append(newTaskSets, sts)
		for id, tsk := range tasks2 {
			newTasks[id] = tsk
		}
	}

	if len(oldTasks) != len(newTasks) {
		t.Fatalf("mismatched task count: old=%d new=%d", len(oldTasks), len(newTasks))
	}
	ids := make([]string, 0, len(oldTasks))
	for id := range oldTasks {
		if newTasks[id] == nil {
			t.Fatalf("missing id %q in new graph", id)
		}
		ids = append(ids, id)
	}

	if err := arrangeSnapTaskSetsLinkageAndRestart(stOld, nil, oldTaskSets); err != nil {
		t.Fatalf("arrangeSnapTaskSetsLinkageAndRestart returned error: %v", err)
	}
	if err := arrangeSnapInstallTaskSets(stNew, nil, newTaskSets); err != nil {
		t.Fatalf("arrangeSnapInstallTaskSets returned error: %v", err)
	}

	oldAdj := buildAdjacencyByTestID(t, oldTasks)
	newAdj := buildAdjacencyByTestID(t, newTasks)

	oldReach := computeReachability(ids, oldAdj)
	newReach := computeReachability(ids, newAdj)

	diffCount := 0
	for _, u := range ids {
		for _, v := range ids {
			if u == v {
				continue
			}
			old := oldReach[u][v]
			new := newReach[u][v]
			if old == new {
				continue
			}
			diffCount++

			if !strings.HasSuffix(v, ":download") {
				t.Fatalf("unexpected ordering difference %q -> %q (old=%v new=%v)", u, v, old, new)
			}
			if !(old && !new) {
				t.Fatalf("ordering difference was not a relaxation %q -> %q (old=%v new=%v)", u, v, old, new)
			}
		}
	}

	if diffCount == 0 {
		t.Fatalf("expected at least one ordering difference, got none")
	}
}
