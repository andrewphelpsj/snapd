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
	"testing"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/assertstest"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/snaptest"
)

type trivialDeviceContextForLaneMergeTest struct {
	model *asserts.Model
}

func (dc *trivialDeviceContextForLaneMergeTest) GroundContext() DeviceContext { return dc }
func (dc *trivialDeviceContextForLaneMergeTest) Store() StoreService          { return nil }
func (dc *trivialDeviceContextForLaneMergeTest) ForRemodeling() bool          { return false }
func (dc *trivialDeviceContextForLaneMergeTest) SystemMode() string           { return "run" }

func (dc *trivialDeviceContextForLaneMergeTest) RunMode() bool { return true }
func (dc *trivialDeviceContextForLaneMergeTest) Classic() bool { return dc.model.Classic() }

func (dc *trivialDeviceContextForLaneMergeTest) Kernel() string { return dc.model.Kernel() }
func (dc *trivialDeviceContextForLaneMergeTest) Base() string   { return dc.model.Base() }
func (dc *trivialDeviceContextForLaneMergeTest) Gadget() string { return dc.model.Gadget() }

func (dc *trivialDeviceContextForLaneMergeTest) HasModeenv() bool {
	return dc.model.Grade() != asserts.ModelGradeUnset
}

func (dc *trivialDeviceContextForLaneMergeTest) IsCoreBoot() bool    { return dc.model.Kernel() != "" }
func (dc *trivialDeviceContextForLaneMergeTest) IsClassicBoot() bool { return !dc.IsCoreBoot() }

func (dc *trivialDeviceContextForLaneMergeTest) Model() *asserts.Model { return dc.model }

func modelBaseCore20ForLaneMergeTest() *asserts.Model {
	model := map[string]any{
		"type":         "model",
		"authority-id": "brand",
		"series":       "16",
		"brand-id":     "brand",
		"model":        "baz-3000",
		"architecture": "amd64",
		"base":         "core20",
		"grade":        "dangerous",
		"timestamp":    "2018-01-01T08:00:00+00:00",
		"snaps": []any{
			map[string]any{
				"name": "kernel",
				"id":   snaptest.AssertedSnapID("kernel"),
				"type": "kernel",
			},
			map[string]any{
				"name": "brand-gadget",
				"id":   snaptest.AssertedSnapID("brand-gadget"),
				"type": "gadget",
			},
		},
	}
	return assertstest.FakeAssertion(model, nil).(*asserts.Model)
}

func snapInstallTaskSetForLaneMergeTest(st *state.State, snapName string, snapType snap.Type, base string, lane int) snapInstallTaskSet {
	snapsup := SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: snapName,
			SnapID:   snapName,
			Revision: snap.R(1),
		},
		Type: snapType,
		Base: base,
	}

	beforeLocal := st.NewTask("prerequisites", "...")
	beforeLocal.Set("snap-setup", snapsup)

	unlink := st.NewTask("unlink-snap", "...")
	link := st.NewTask("link-snap", "...")
	link.WaitFor(unlink)

	autoConnect := st.NewTask("auto-connect", "...")
	autoConnect.WaitFor(link)

	ts := state.NewTaskSet(beforeLocal, unlink, link, autoConnect)
	ts.JoinLane(lane)

	return snapInstallTaskSet{
		snapsup: snapsup,
		ts:      ts,

		beforeLocalSystemModificationsTasks: []*state.Task{beforeLocal},
		beforeReboot:                        []*state.Task{unlink, link},
		postReboot:                          []*state.Task{autoConnect},
	}
}

func assertUniqueLaneMembership(t *testing.T, task *state.Task, want ...int) {
	t.Helper()
	lanes := task.Lanes()
	seen := make(map[int]bool, len(lanes))
	for _, l := range lanes {
		if seen[l] {
			t.Fatalf("task %q has duplicate lane %d in %v", task.Kind(), l, lanes)
		}
		seen[l] = true
	}
	for _, l := range want {
		if !seen[l] {
			t.Fatalf("task %q lanes %v missing lane %d", task.Kind(), lanes, l)
		}
	}
}

func TestArrangeSnapInstallTaskSetsMergesLanesWithoutDuplicates(t *testing.T) {
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

	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	baseLane := 1
	kernelLane := 2

	baseSts := snapInstallTaskSetForLaneMergeTest(st, "core20", snap.TypeBase, "core20", baseLane)
	kernelSts := snapInstallTaskSetForLaneMergeTest(st, "kernel", snap.TypeKernel, "core20", kernelLane)

	if err := arrangeSnapInstallTaskSets(st, nil, []snapInstallTaskSet{baseSts, kernelSts}); err != nil {
		t.Fatalf("arrangeSnapInstallTaskSets returned error: %v", err)
	}

	for _, sts := range []snapInstallTaskSet{baseSts, kernelSts} {
		for _, slice := range [][]*state.Task{
			sts.beforeLocalSystemModificationsTasks,
			sts.beforeReboot,
			sts.postReboot,
		} {
			for _, task := range slice {
				assertUniqueLaneMembership(t, task, baseLane, kernelLane)
			}
		}
	}
}
