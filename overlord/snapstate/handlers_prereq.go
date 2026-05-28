// -*- Mode: Go; indent-tabs-mode: t -*-
/*
 * Copyright (C) 2026 Canonical Ltd
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
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/overlord/ifacestate/ifacerepo"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/release"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/timings"
	"gopkg.in/tomb.v2"
)

// timeout for tasks to check if the prerequisites are ready
var prerequisitesRetryTimeout = 10 * time.Second

func (m *SnapManager) doPrerequisites(t *state.Task, _ *tomb.Tomb) error {
	st := t.State()
	st.Lock()
	defer st.Unlock()

	tm := state.TimingsForTask(t)
	defer tm.Save(st)

	// check if we need to inject tasks to install core
	snapsup, _, err := snapSetupAndState(t)
	if err != nil {
		return err
	}

	// snapd/os/base/kernel/gadget cannot have prerequisites other than the
	// models default base (or core) which is installed anyway
	switch snapsup.Type {
	case snap.TypeSnapd, snap.TypeOS, snap.TypeBase, snap.TypeKernel, snap.TypeGadget:
		return nil
	}

	dctx, err := DeviceCtx(st, t, nil)
	if err != nil {
		return err
	}

	// if we are remodeling, then we should return early due to the way that
	// tasks are ordered by the remodeling code. specifically, all snap
	// downloads during a remodel happen prior to snap installation. thus,
	// we cannot wait for snaps to be installed here. see remodelTasks for
	// more information on how the tasks are ordered.
	if dctx.ForRemodeling() {
		return nil
	}

	// if a previous version of snapd persisted Prereq only, fill the contentAttrs.
	// There will be no content attrs, so it will not update an outdated default provider
	if len(snapsup.PrereqContentAttrs) == 0 && len(snapsup.Prereq) != 0 {
		snapsup.PrereqContentAttrs = make(map[string][]string, len(snapsup.Prereq))

		for _, prereq := range snapsup.Prereq {
			snapsup.PrereqContentAttrs[prereq] = nil
		}
	}

	// If transactional, use a single lane for all tasks, so when one fails the
	// changes for all affected snaps will be undone. Otherwise, have different
	// lanes per snap so failures only affect the culprit snap.
	flags := Flags{
		Transaction: snapsup.Transaction,

		// TODO: as a temporary workaround for a bug that occurs when a snap updates
		// a prereq, we disable rerefreshes.
		//
		// specifically, if the snap that pulls in the prereq contains a configure
		// hook that creates some tasks via snapctl, then those tasks will end up
		// waiting on the check-rerefresh task for the updated prereq. the
		// check-rerefresh task panics if any tasks are found to be waiting on it.
		NoReRefresh: true,

		// we're calling an API facing call which would otherwise be normally
		// expected to produce a delayed effects taskset, but since the desire
		// is to inject the tasksets into the current change, set the flag to
		// avoid generating one
		NoDelayedSideEffects: true,
	}
	if flags.Transaction == client.TransactionAllSnaps {
		lanes := t.Lanes()
		if len(lanes) != 1 {
			return fmt.Errorf("internal error: more than one lane (%d) on a transactional action", len(lanes))
		}

		flags.Lane = lanes[0]
	} else {
		flags.Transaction = client.TransactionPerSnap
	}

	base := defaultCoreSnapName
	if snapsup.Base != "" {
		base = snapsup.Base
	}

	return installPrereqs(t, base, snapsup.PrereqContentAttrs, tm, Options{
		Flags:     flags,
		UserID:    snapsup.UserID,
		DeviceCtx: dctx,
		ConflictOptions: ConflictOptions{
			FromChange: t.Change().ID(),
			// setting this lets us use snap update conflict detection, even
			// though we're passing in the change ID
			DoNotIgnoreFromChangeInTaskConflictCheck: true,
		},
	})
}

func defaultBaseSnapsChannel() string {
	channel := os.Getenv("SNAPD_BASES_CHANNEL")
	if channel == "" {
		return "stable"
	}
	return channel
}

func defaultSnapdSnapsChannel() string {
	channel := os.Getenv("SNAPD_SNAPD_CHANNEL")
	if channel == "" {
		return "stable"
	}
	return channel
}

func defaultPrereqSnapsChannel() string {
	channel := os.Getenv("SNAPD_PREREQS_CHANNEL")
	if channel == "" {
		return "stable"
	}
	return channel
}

func installPrereqs(t *state.Task, base string, prereq map[string][]string, tm timings.Measurer, opts Options) error {
	st := t.State()

	var seedTS *SeedRefreshTaskSet
	trackSeedTS := func(ts *state.TaskSet) error {
		if seedTS != nil {
			return nil
		}

		enabled, err := seedRefreshEnabled(st)
		if err != nil {
			return err
		}

		if !enabled || ts == nil || t.Has("prerequisites-sync") {
			return nil
		}

		seedTS, err = PendingSeedRefreshTasks(ts)
		if err != nil {
			return err
		}

		// ensure that future snap refreshes don't trigger more seed refreshes
		opts.NoSeedRefresh = seedTS != nil

		return nil
	}

	if err := trackSeedTS(state.NewTaskSet(t.Change().Tasks()...)); err != nil {
		return err
	}

	// We try to install all wanted snaps. If one snap cannot be installed
	// because of change conflicts or similar we retry. Only if all snaps can be
	// installed together we add the tasks to the change.
	var tss []*state.TaskSet
	for prereqName, contentAttrs := range prereq {
		var ts *state.TaskSet
		var err error
		timings.Run(tm, "install-prereq", fmt.Sprintf("install %q", prereqName), func(timings.Measurer) {
			ts, err = ensurePrerequisite(t, contentAttrs, StoreSnap{
				InstanceName: prereqName,
				RevOpts: RevisionOptions{
					Channel: defaultPrereqSnapsChannel(),
				},
			}, opts)
		})
		if err != nil {
			return prereqError("prerequisite", prereqName, err)
		}
		if ts == nil {
			continue
		}
		if err := trackSeedTS(ts); err != nil {
			return err
		}
		tss = append(tss, ts)
	}

	var baseTS *state.TaskSet
	if base != "none" {
		var err error
		timings.Run(tm, "install-prereq", fmt.Sprintf("install base %q", base), func(timings.Measurer) {
			opts := opts
			opts.Flags.RequireTypeBase = true
			baseTS, err = ensurePrerequisite(t, nil, StoreSnap{
				InstanceName: base,
				RevOpts: RevisionOptions{
					Channel: defaultBaseSnapsChannel(),
				},
			}, opts)
		})
		if err != nil {
			return prereqError("snap base", base, err)
		}
		if err := trackSeedTS(baseTS); err != nil {
			return err
		}
	}

	installSnapd, err := considerSnapdAsPrereq(st)
	if err != nil {
		return err
	}

	var snapdTS *state.TaskSet
	if installSnapd {
		timings.Run(tm, "install-prereq", "install snapd", func(timings.Measurer) {
			snapdTS, err = ensurePrerequisite(t, nil, StoreSnap{
				InstanceName: "snapd",
				RevOpts: RevisionOptions{
					Channel: defaultSnapdSnapsChannel(),
				},
			}, opts)
		})
		if err != nil {
			return prereqError("system snap", "snapd", err)
		}
		if err := trackSeedTS(snapdTS); err != nil {
			return err
		}
	}

	for _, ts := range append([]*state.TaskSet{snapdTS, baseTS}, tss...) {
		if seedTS == nil || ts == nil {
			continue
		}

		if err := maybeMergeLateSeedRefreshPrereq(seedTS, opts.DeviceCtx, ts); err != nil {
			return err
		}
	}

	chg := t.Change()
	// add all required snaps, no ordering, this will be done in the
	// auto-connect task handler
	for _, ts := range tss {
		chg.AddAll(ts)
	}
	// add the base if needed, prereqs else must wait on this
	if baseTS != nil {
		for _, t := range chg.Tasks() {
			t.WaitAll(baseTS)
		}
		chg.AddAll(baseTS)
	}
	// add snapd if needed, everything must wait on this
	if snapdTS != nil {
		for _, t := range chg.Tasks() {
			t.WaitAll(snapdTS)
		}
		chg.AddAll(snapdTS)
	}

	// make sure that the new change is committed to the state
	// together with marking this task done
	t.SetStatus(state.DoneStatus)

	return nil
}

// considerSnapdAsPrereq returns true if we should install snapd as a
// prerequisite. Returns true on classic systems that are already seeded. Not
// allowed on Ubuntu Core systems, this requires remodeling.
func considerSnapdAsPrereq(st *state.State) (bool, error) {
	installed, err := isInstalled(st, "snapd")
	if err != nil {
		return false, err
	}

	// consider the state of seeding to avoid seed conflict error
	var seeded bool
	if err := st.Get("seeded", &seeded); err != nil && !errors.Is(err, state.ErrNoState) {
		return false, err
	}

	return release.OnClassic && seeded && !installed, nil
}

func skipOrRetryPrereq(prereqs *state.Task, snapName string, required bool) (bool, error) {
	st := prereqs.State()

	link, err := findLinkSnapTaskForSnap(st, snapName)
	if err != nil {
		return false, err
	}

	retry := &state.Retry{After: prerequisitesRetryTimeout}
	const skip = true

	// nothing in flight, don't skip at all
	if link == nil {
		return false, nil
	}

	// the first prerequisites (there are two in a snap's installation graph)
	// task must not block on work already scheduled in this same change.
	// the secondary prerequisites sync task is responsible for polling until
	// that in-flight work has completed.
	if !prereqs.Has("prerequisites-sync") && link.Change().ID() == prereqs.Change().ID() {
		return skip, nil
	}

	// in flight, but not a required prereq
	if !required {
		// already in the same change, just skip it
		if link.Change().ID() == prereqs.Change().ID() {
			return skip, nil
		}
		// not in this change, poll until that task is done
		return false, retry
	}

	// if this snap is already waiting behind the in-flight refresh, this
	// "prerequisites" task does not need to wait for that snap out-of-band as
	// well.
	//
	// snapd is special, we'll always wait for that to be fully done before
	// progressing this task
	if snapName != "snapd" {
		waiting, err := snapWaitsForLinkInSameLane(prereqs, link)
		if err != nil {
			return false, err
		}

		if waiting {
			return skip, nil
		}
	}

	if willWaitOn(link, prereqs) {
		return false, fmt.Errorf(
			"internal error: prerequisites task cannot wait on task %[1]q because task %[1]q is waiting on the prerequisites task",
			link.ID(),
		)
	}

	return false, retry
}

func ensurePrerequisite(t *state.Task, contentAttrs []string, sn StoreSnap, opts Options) (*state.TaskSet, error) {
	st := t.State()

	// as a special case, we allow the core snap to satisfy a core16 requirement
	if sn.InstanceName == "core16" {
		installed, err := isInstalled(st, "core")
		if err != nil {
			return nil, err
		}

		// this is safe since bases are not content-providers. thus, they will
		// never need an update. note that this also skips any retry behavior,
		// but is consistent with the current implementation.
		if installed {
			return nil, nil
		}
	}

	required := sn.InstanceName == "snapd" || opts.Flags.RequireTypeBase
	skip, err := skipOrRetryPrereq(t, sn.InstanceName, required)
	if err != nil {
		return nil, err
	}

	if skip {
		return nil, nil
	}

	syncTask := t.Has("prerequisites-sync")

	installed, err := isInstalled(st, sn.InstanceName)
	if err != nil {
		return nil, err
	}

	var ts *state.TaskSet
	if !installed {
		if syncTask {
			if required {
				return nil, fmt.Errorf("prerequisite %q is not available during prerequisites synchronization", sn.InstanceName)
			}

			// not a required prereq, skip it
			return nil, nil
		}
		_, ts, err = InstallOne(context.TODO(), st, StoreInstallGoal(sn), opts)
	} else {
		if syncTask {
			provided, err := hasAllContentAttrs(st, sn.InstanceName, contentAttrs)
			if err != nil {
				return nil, err
			}

			if required && !provided {
				return nil, fmt.Errorf("prerequisite %q is missing required content during prerequisites synchronization", sn.InstanceName)
			}

			// not a required prereq, skip it
			return nil, nil
		}
		ts, err = maybeUpdateContentProvider(t, sn.InstanceName, contentAttrs, opts)
	}
	if err != nil {
		var cerr *ChangeConflictError
		if errors.As(err, &cerr) {
			// conflicted with an install in the same change, just skip
			if cerr.ChangeID == t.Change().ID() {
				return nil, nil
			}

			return nil, &state.Retry{After: prerequisitesRetryTimeout}
		}
		return nil, err
	}
	return ts, nil
}

func maybeUpdateContentProvider(t *state.Task, snapName string, contentAttrs []string, opts Options) (*state.TaskSet, error) {
	st := t.State()
	provided, err := hasAllContentAttrs(st, snapName, contentAttrs)
	if err != nil {
		return nil, err
	}
	if provided {
		return nil, nil
	}

	ts, err := UpdateOne(context.TODO(), st, StoreUpdateGoal(StoreUpdate{
		InstanceName: snapName,
	}), nil, opts)
	if err != nil {
		var cerr *ChangeConflictError
		if errors.As(err, &cerr) {
			// if we aren't seeded, then it's too early to do any updates and we
			// cannot handle this during seeding, so expect the
			// ChangeConflictError in this scenario.
			if cerr.ChangeKind == "seed" {
				t.Logf("cannot update %q during seeding, will not have required content %q: %s", snapName, strings.Join(contentAttrs, ", "), cerr)
				return nil, nil
			}

			return nil, err
		}

		// don't propagate error to avoid failing the main install since the
		// content provider is (for now) a soft dependency
		t.Logf("cannot update %q, will not have required content %q: %s", snapName, strings.Join(contentAttrs, ", "), err)
		return nil, nil
	}

	return ts, nil
}

// hasAllContentAttrs checks if the snap has slots with "content" attributes
// matching the ones that the snap being installed requires
func hasAllContentAttrs(st *state.State, snapName string, requiredContentAttrs []string) (bool, error) {
	providedContentAttrs := make(map[string]bool)
	repo := ifacerepo.Get(st)

	for _, slot := range repo.Slots(snapName) {
		if slot.Interface != "content" {
			continue
		}

		val, ok := slot.Lookup("content")
		if !ok {
			continue
		}

		contentAttr, ok := val.(string)
		if !ok {
			return false, fmt.Errorf("expected 'content' attribute of slot '%s' (snap: '%s') to be string but was %s", slot.Name, snapName, reflect.TypeOf(val))
		}

		providedContentAttrs[contentAttr] = true
	}

	for _, contentAttr := range requiredContentAttrs {
		if _, ok := providedContentAttrs[contentAttr]; !ok {
			return false, nil
		}
	}

	return true, nil
}

func findLinkSnapTaskForSnap(st *state.State, snapName string) (*state.Task, error) {
	for _, chg := range st.Changes() {
		if chg.IsReady() {
			continue
		}

		t, err := maybeFindTaskInChangeForSnap(chg, "link-snap", snapName)
		if err != nil {
			return nil, err
		}

		if t != nil {
			return t, nil
		}
	}

	return nil, nil
}

func isInstalled(st *state.State, snapName string) (bool, error) {
	var snapState SnapState
	err := Get(st, snapName, &snapState)
	if err != nil && !errors.Is(err, state.ErrNoState) {
		return false, err
	}
	return snapState.IsInstalled(), nil
}

// willWaitOn returns true if graph waits (directly or transitively) on target.
func willWaitOn(graph *state.Task, target *state.Task) bool {
	seen := make(map[string]bool)
	queue := append([]*state.Task(nil), graph.WaitTasks()...)
	for i := 0; i < len(queue); i++ {
		current := queue[i]
		if seen[current.ID()] {
			continue
		}

		seen[current.ID()] = true
		if current.ID() == target.ID() {
			return true
		}

		for _, child := range current.WaitTasks() {
			if !seen[child.ID()] {
				queue = append(queue, child)
			}
		}
	}

	return false
}

// tasksShareLane reports whether the two tasks share at least one lane.
func tasksShareLane(t, other *state.Task) bool {
	lanes := make(map[int]bool, len(t.Lanes()))
	for _, lane := range t.Lanes() {
		lanes[lane] = true
	}

	for _, lane := range other.Lanes() {
		if lanes[lane] {
			return true
		}
	}

	return false
}

// snapWaitsForLinkInSameLane reports whether another task for the same snap in
// the same lane is already ordered behind the prerequisite's link-snap task.
func snapWaitsForLinkInSameLane(prereqs *state.Task, link *state.Task) (bool, error) {
	// if they don't share a change, then there won't be dependencies already
	// established
	if prereqs.Change().ID() != link.Change().ID() {
		return false, nil
	}

	chg := prereqs.Change()

	instanceName, ok := instanceNameFromTask(prereqs)
	if !ok {
		return false, errors.New("internal error: cannot find instance name on prerequisites task")
	}

	for _, t := range chg.Tasks() {
		if t.ID() == prereqs.ID() {
			continue
		}

		if !tasksShareLane(prereqs, t) {
			continue
		}

		other, ok := instanceNameFromTask(t)
		if !ok || other != instanceName {
			continue
		}

		// this check could be made stronger by enforcing that the first local
		// modification task for the snap waits on the prereq's link-snap task,
		// but we don't have a great way to find that task at this point in
		// time, since we don't have access to edges any more.
		//
		// in short, this is somewhat of a heuristic. we'd need to enumerate all
		// before-local-modification tasks if we want to make this check better.
		if willWaitOn(t, link) {
			return true, nil
		}
	}

	return false, nil
}

func instanceNameFromTask(t *state.Task) (string, bool) {
	snapsup, err := TaskSnapSetup(t)
	if err != nil {
		return "", false
	}
	return snapsup.InstanceName(), true
}

func prereqError(what, snapName string, err error) error {
	if _, ok := err.(*state.Retry); ok {
		return err
	}
	return fmt.Errorf("cannot install %s %q: %v", what, snapName, err)
}

func maybeFindTaskInChangeForSnap(chg *state.Change, kind, snapName string) (*state.Task, error) {
	for _, t := range chg.Tasks() {
		if t.Status().Ready() || t.Kind() != kind {
			continue
		}

		snapsup, err := TaskSnapSetup(t)
		if err != nil {
			return nil, err
		}
		if snapsup.InstanceName() == snapName {
			return t, nil
		}
	}

	return nil, nil
}
