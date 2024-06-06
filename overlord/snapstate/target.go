// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016-2024 Canonical Ltd
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
	"sort"

	"github.com/snapcore/snapd/asserts/snapasserts"
	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/i18n"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/overlord/snapstate/backend"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/naming"
	"github.com/snapcore/snapd/store"
	"github.com/snapcore/snapd/strutil"
)

// Options contains optional parameters for the snapstate operations. All of
// these fields are optional and can be left unset. The options in this struct
// apply to all snaps that are part of an operation. Options that apply to
// individual snaps can be found in RevisionOptions.
type Options struct {
	// Flags contains flags that apply to the entire operation.
	Flags Flags
	// UserID is the ID of the user that is performing the operation.
	UserID int
	// DeviceCtx is an optional device context that will be used during the
	// operation.
	DeviceCtx DeviceContext
	// PrereqTracker is an optional prereq tracker that will be used to keep
	// track of all snaps (explicitly requested and implicitly required snaps)
	// that might need to be installed during the operation.
	PrereqTracker PrereqTracker
	// FromChange is the change that triggered the operation.
	FromChange string
	// Seed should be true while seeding the device. This indicates that we
	// shouldn't require that the device is seeded before installing/updating
	// snaps.
	Seed bool
	// ExpectOneSnap is a boolean flag indicating that this operation is expected
	// to only operate on one snap (excluding any prerequisite snaps that may be
	// required). If this is true, then the operation will fail if more than one
	// snap is being operated on. This flag primarily exists to support the
	// pre-existing behavior of calling InstallMany with one snap vs calling
	// Install.
	ExpectOneSnap bool
}

// target represents the data needed to setup a snap for installation.
type target struct {
	// setup is a partially initialized SnapSetup that contains the data needed
	// to find the snap file that will be installed.
	setup SnapSetup
	// info contains the snap.info for the snap to be installed.
	info *snap.Info
	// snapst is the current state of the target snap, prior to installation.
	// This must be retrieved prior to unlocking the state for any reason (for
	// example, talking to the store).
	snapst SnapState
	// components is a list of components to install with this snap.
	components []componentTarget
}

// setups returns the completed SnapSetup and slice of ComponentSetup structs
// for the target snap.
func (t *target) setups(st *state.State, opts Options) (SnapSetup, []ComponentSetup, error) {
	snapUserID, err := userIDForSnap(st, &t.snapst, opts.UserID)
	if err != nil {
		return SnapSetup{}, nil, err
	}

	flags, err := earlyChecks(st, &t.snapst, t.info, opts.Flags)
	if err != nil {
		return SnapSetup{}, nil, err
	}

	// to match the behavior of the original Update and UpdateMany, we only
	// allow updating ignoring validation sets if we are working with
	// exactly one snap
	if !opts.ExpectOneSnap {
		flags.IgnoreValidation = t.snapst.IgnoreValidation
	}

	compsups := make([]ComponentSetup, 0, len(t.components))
	for _, comp := range t.components {
		compsups = append(compsups, comp.compsup())
	}

	providerContentAttrs := defaultProviderContentAttrs(st, t.info, opts.PrereqTracker)
	return SnapSetup{
		Channel:      t.setup.Channel,
		CohortKey:    t.setup.CohortKey,
		DownloadInfo: t.setup.DownloadInfo,
		SnapPath:     t.setup.SnapPath,

		Base:               t.info.Base,
		Prereq:             getKeys(providerContentAttrs),
		PrereqContentAttrs: providerContentAttrs,
		UserID:             snapUserID,
		Flags:              flags.ForSnapSetup(),
		SideInfo:           &t.info.SideInfo,
		Type:               t.info.Type(),
		Version:            t.info.Version,
		PlugsOnly:          len(t.info.Slots) == 0,
		InstanceKey:        t.info.InstanceKey,
		ExpectedProvenance: t.info.SnapProvenance,
	}, compsups, nil
}

// componentTarget represents the data needed to setup a component for installation.
type componentTarget struct {
	// setup is a partially initialized ComponentSetup struct that contains the
	// data needed to find the component that will be installed.
	setup ComponentSetup
	// info contains the snap.ComponentInfo for the component to be installed.
	info *snap.ComponentInfo
}

func (c *componentTarget) compsup() ComponentSetup {
	return ComponentSetup{
		DownloadInfo: c.setup.DownloadInfo,
		CompPath:     c.setup.CompPath,
		CompSideInfo: &c.info.ComponentSideInfo,
		CompType:     c.info.Type,
	}
}

// UpdateSummary contains the data that describes an update, including a list of
// Target structs that represent the snaps that are to be updated.
//
// TODO: better name
type UpdateSummary struct {
	// Requested is the list of snaps that were requested to be updated. If
	// RefreshAll is true, then this list should be empty.
	Requested []string
	// RefreshAll is true if all snaps on the system are being refreshed (could
	// be either an auto-refresh or something like a manual "snap refresh").
	// This mostly has the effect of ignoring some some non-fatal errors.
	RefreshAll bool
	// Targets is the list of snaps that are to be updated. Note that this list
	// does not necessarily match the list of snaps in Requested.
	Targets []target
	// UpdateNotAvailable is a set of snaps that were requested to be updated
	// but did not have an update available. They still may require a channel
	// switch, cohort change, or validation set enforcement change.
	UpdateNotAvailable map[*SnapState]RevisionOptions
}

func (s *UpdateSummary) filter(f func(t target) (bool, error)) error {
	filtered := s.Targets[:0]
	for _, t := range s.Targets {
		ok, err := f(t)
		if err != nil {
			return err
		}

		if ok {
			filtered = append(filtered, t)
		}
	}
	s.Targets = filtered
	return nil
}

func (s *UpdateSummary) targetInfos() []*snap.Info {
	infos := make([]*snap.Info, 0, len(s.Targets))
	for _, t := range s.Targets {
		infos = append(infos, t.info)
	}
	return infos
}

// InstallGoal represents a single snap or a group of snaps to be installed.
type InstallGoal interface {
	// toInstall returns the data needed to setup the snaps for installation.
	toInstall(context.Context, *state.State, Options) ([]target, error)
}

// UpdateGoal represents a single snap or a group of snaps to be installed.
type UpdateGoal interface {
	// Install returns the data needed to setup the snaps for installation.
	toUpdate(context.Context, *state.State, Options) (UpdateSummary, error)
}

// storeInstallGoal implements the InstallGoal interface and represents a group of
// snaps that are to be installed from the store.
type storeInstallGoal struct {
	// snaps is a slice of StoreSnap structs that contains details about the
	// snap to install. It maintains the order of the snaps as they were
	// provided.
	snaps []StoreSnap
}

func (s *storeInstallGoal) find(name string) (StoreSnap, bool) {
	for _, sn := range s.snaps {
		if sn.InstanceName == name {
			return sn, true
		}
	}
	return StoreSnap{}, false
}

// StoreSnap represents a snap that is to be installed from the store.
type StoreSnap struct {
	// InstanceName is the name of snap to install.
	InstanceName string
	// Components is the list of components to install with this snap.
	Components []string
	// RevOpts contains options that apply to the installation of this snap.
	RevOpts RevisionOptions
	// SkipIfPresent indicates that the snap should not be installed if it is already present.
	SkipIfPresent bool
}

// StoreInstallGoal creates a new InstallGoal to install snaps from the store.
// If a snap is provided more than once in the list, the first instance of it
// will be used to provide the installation options.
func StoreInstallGoal(snaps ...StoreSnap) InstallGoal {
	seen := make(map[string]bool, len(snaps))
	unique := make([]StoreSnap, 0, len(snaps))
	for _, sn := range snaps {
		if _, ok := seen[sn.InstanceName]; ok {
			continue
		}

		if sn.RevOpts.Channel == "" {
			sn.RevOpts.Channel = "stable"
		}

		if len(sn.Components) > 0 {
			sn.Components = strutil.Deduplicate(sn.Components)
		}

		seen[sn.InstanceName] = true
		unique = append(unique, sn)
	}

	return &storeInstallGoal{
		snaps: unique,
	}
}

func validateRevisionOpts(opts *RevisionOptions) error {
	if opts.CohortKey != "" && !opts.Revision.Unset() {
		return errors.New("cannot specify revision and cohort")
	}

	// if we're leaving the cohort, clear out any provided cohort key
	if opts.LeaveCohort {
		opts.CohortKey = ""
	}

	return nil
}

var ErrExpectedOneSnap = errors.New("expected exactly one snap to install/update")

// toInstall returns the data needed to setup the snaps from the store for
// installation.
func (s *storeInstallGoal) toInstall(ctx context.Context, st *state.State, opts Options) ([]target, error) {
	if opts.ExpectOneSnap && len(s.snaps) != 1 {
		return nil, ErrExpectedOneSnap
	}

	allSnaps, err := All(st)
	if err != nil {
		return nil, err
	}

	if err := s.validateAndPrune(allSnaps); err != nil {
		return nil, err
	}

	// create a closure that will lazily load the enforced validation sets if
	// any of the targets require them
	var vsets *snapasserts.ValidationSets
	enforcedSets := func() (*snapasserts.ValidationSets, error) {
		if vsets != nil {
			return vsets, nil
		}

		var err error
		vsets, err = EnforcedValidationSets(st)
		if err != nil {
			return nil, err
		}

		return vsets, nil
	}

	actions := make([]*store.SnapAction, 0, len(s.snaps))
	for _, sn := range s.snaps {
		action := &store.SnapAction{
			Action:       "install",
			InstanceName: sn.InstanceName,
			Resources:    sn.Components,
		}

		if err := completeStoreAction(action, sn.RevOpts, opts.Flags.IgnoreValidation, enforcedSets); err != nil {
			return nil, err
		}

		actions = append(actions, action)
	}

	curSnaps, err := currentSnaps(st)
	if err != nil {
		return nil, err
	}

	refreshOpts, err := refreshOptions(st, nil)
	if err != nil {
		return nil, err
	}

	user, err := userFromUserID(st, opts.UserID)
	if err != nil {
		return nil, err
	}

	str := Store(st, opts.DeviceCtx)

	st.Unlock() // calls to the store should be done without holding the state lock
	results, _, err := str.SnapAction(context.TODO(), curSnaps, actions, nil, user, refreshOpts)
	st.Lock()

	if err != nil {
		if opts.ExpectOneSnap {
			return nil, singleActionResultErr(actions[0].InstanceName, actions[0].Action, err)
		}
		return nil, err
	}

	installs := make([]target, 0, len(results))
	for _, r := range results {
		sn, ok := s.find(r.InstanceName())
		if !ok {
			return nil, fmt.Errorf("store returned unsolicited snap action: %s", r.InstanceName())
		}

		snapst, ok := allSnaps[r.InstanceName()]
		if !ok {
			snapst = &SnapState{}
		}

		// TODO: is it safe to pull the channel from here? i'm not sure what
		// this will actually look like as a response from the real store
		channel := r.RedirectChannel
		if r.RedirectChannel == "" {
			channel = sn.RevOpts.Channel
		}

		comps, err := requestedComponentsFromActionResult(sn, r)
		if err != nil {
			return nil, fmt.Errorf("cannot extract components from snap resources: %w", err)
		}

		installs = append(installs, target{
			setup: SnapSetup{
				DownloadInfo: &r.DownloadInfo,
				Channel:      channel,
				CohortKey:    sn.RevOpts.CohortKey,
			},
			info:       r.Info,
			snapst:     *snapst,
			components: comps,
		})
	}

	return installs, err
}

func requestedComponentsFromActionResult(sn StoreSnap, sar store.SnapActionResult) ([]componentTarget, error) {
	mapping := make(map[string]store.SnapResourceResult, len(sar.Resources))
	for _, res := range sar.Resources {
		mapping[res.Name] = res
	}

	installables := make([]componentTarget, 0, len(sn.Components))
	for _, comp := range sn.Components {
		res, ok := mapping[comp]
		if !ok {
			return nil, fmt.Errorf("cannot find component %q in snap resources", comp)
		}

		installable, err := componentFromResource(comp, res, sar.Info)
		if err != nil {
			return nil, err
		}

		installables = append(installables, installable)
	}
	return installables, nil
}

func componentFromResource(name string, sar store.SnapResourceResult, info *snap.Info) (componentTarget, error) {
	comp, ok := info.Components[name]
	if !ok {
		return componentTarget{}, fmt.Errorf("%q is not a component for snap %q", name, info.SnapName())
	}

	if typ := fmt.Sprintf("component/%s", comp.Type); typ != sar.Type {
		return componentTarget{}, fmt.Errorf("inconsistent component type (%q in snap, %q in component)", typ, sar.Type)
	}

	compName := naming.NewComponentRef(info.SnapName(), name)

	return componentTarget{
		setup: ComponentSetup{
			DownloadInfo: &sar.DownloadInfo,
		},
		info: &snap.ComponentInfo{
			Component: compName,
			Type:      comp.Type,
			Version:   sar.Version,
			ComponentSideInfo: snap.ComponentSideInfo{
				Component: compName,
				Revision:  snap.R(sar.Revision),
			},
		},
	}, nil
}

func completeStoreAction(action *store.SnapAction, revOpts RevisionOptions, ignoreValidation bool, enforcedSets func() (*snapasserts.ValidationSets, error)) error {
	if action.Action == "" {
		return fmt.Errorf("internal error: action must be set")
	}

	if action.InstanceName == "" {
		return fmt.Errorf("internal error: instance name must be set")
	}

	action.Channel = revOpts.Channel
	action.CohortKey = revOpts.CohortKey
	action.Revision = revOpts.Revision

	switch {
	case ignoreValidation:
		// caller requested that we ignore validation sets, nothing to do
		action.Flags = store.SnapActionIgnoreValidation
	case len(revOpts.ValidationSets) > 0:
		// caller provided some validation sets, nothing to do but send them
		// to the store
		action.ValidationSets = revOpts.ValidationSets
	default:
		vsets, err := enforcedSets()
		if err != nil {
			return err
		}

		// if the caller didn't provide any validation sets, make sure that
		// the snap is allowed by all of the enforced validation sets
		invalidSets, err := vsets.CheckPresenceInvalid(naming.Snap(action.InstanceName))
		if err != nil {
			if _, ok := err.(*snapasserts.PresenceConstraintError); !ok {
				return err
			} // else presence is optional or required, carry on
		}

		if len(invalidSets) > 0 {
			verb := "install"
			if action.Action == "refresh" {
				verb = "update"
			}

			return fmt.Errorf(
				"cannot %s snap %q due to enforcing rules of validation set %s",
				verb,
				action.InstanceName,
				snapasserts.ValidationSetKeySlice(invalidSets).CommaSeparated(),
			)
		}

		requiredSets, requiredRev, err := vsets.CheckPresenceRequired(naming.Snap(action.InstanceName))
		if err != nil {
			return err
		}

		// make sure that the caller-requested revision matches the revision
		// required by the enforced validation sets
		if !requiredRev.Unset() && !revOpts.Revision.Unset() && requiredRev != revOpts.Revision {
			return invalidRevisionError(action, requiredSets, revOpts.Revision, requiredRev)
		}

		// TODO: handle validation sets and components here

		action.ValidationSets = requiredSets

		if !requiredRev.Unset() {
			// make sure that we use the revision required by the enforced
			// validation sets
			action.Revision = requiredRev

			// we ignore the cohort if a validation set requires that the
			// snap is pinned to a specific revision
			action.CohortKey = ""
		}
	}

	// clear out the channel if we're requesting a specific revision, which
	// could be because the user requested a specific revision or because a
	// validation set requires it
	if !action.Revision.Unset() {
		action.Channel = ""
	}

	return nil
}

func invalidRevisionError(a *store.SnapAction, sets []snapasserts.ValidationSetKey, requested, required snap.Revision) error {
	verb := "install"
	preposition := "at"
	if a.Action == "refresh" {
		verb = "update"
		preposition = "to"
	}

	return fmt.Errorf(
		"cannot %s snap %q %s revision %s without --ignore-validation, revision %s is required by validation sets: %s",
		verb,
		a.InstanceName,
		preposition,
		requested,
		required,
		snapasserts.ValidationSetKeySlice(sets).CommaSeparated(),
	)
}

func (s *storeInstallGoal) validateAndPrune(installedSnaps map[string]*SnapState) error {
	uninstalled := s.snaps[:0]
	for _, t := range s.snaps {
		if err := snap.ValidateInstanceName(t.InstanceName); err != nil {
			return fmt.Errorf("invalid instance name: %v", err)
		}

		if err := validateRevisionOpts(&t.RevOpts); err != nil {
			return fmt.Errorf("invalid revision options for snap %q: %w", t.InstanceName, err)
		}

		snapst, ok := installedSnaps[t.InstanceName]
		if ok && snapst.IsInstalled() {
			if !t.SkipIfPresent {
				return &snap.AlreadyInstalledError{Snap: t.InstanceName}
			}
			continue
		}

		uninstalled = append(uninstalled, t)
	}

	s.snaps = uninstalled

	return nil
}

// storeInstallGoal implements the Target interface and represents a group of
// snaps that are to be installed from the store.
type storeUpdateGoal struct {
	snaps map[string]StoreUpdate
}

// StoreUpdate represents a snap that is to be updated from the store.
type StoreUpdate struct {
	// InstanceName is the instancename of snap to update.
	InstanceName string
	// RevOpts contains options that apply to the update of this snap.
	RevOpts RevisionOptions
}

func StoreUpdateGoal(snaps ...StoreUpdate) UpdateGoal {
	mapping := make(map[string]StoreUpdate, len(snaps))
	for _, sn := range snaps {
		if _, ok := mapping[sn.InstanceName]; ok {
			continue
		}

		mapping[sn.InstanceName] = sn
	}

	return &storeUpdateGoal{
		snaps: mapping,
	}
}

func (s *storeUpdateGoal) toUpdate(ctx context.Context, st *state.State, opts Options) (UpdateSummary, error) {
	if opts.ExpectOneSnap && len(s.snaps) != 1 {
		return UpdateSummary{}, ErrExpectedOneSnap
	}

	if err := validateAndInitStoreUpdates(st, s.snaps, opts); err != nil {
		return UpdateSummary{}, err
	}

	user, err := userFromUserID(st, opts.UserID)
	if err != nil {
		return UpdateSummary{}, err
	}

	refreshOpts := &store.RefreshOptions{Scheduled: opts.Flags.IsAutoRefresh}
	summary, err := refreshCandidatesV2(ctx, st, s.snaps, user, refreshOpts, opts)
	if err != nil {
		return UpdateSummary{}, err
	}

	return summary, nil
}

func validateAndInitStoreUpdates(st *state.State, updates map[string]StoreUpdate, opts Options) error {
	snapstates, err := All(st)
	if err != nil {
		return err
	}

	for _, sn := range updates {
		snapst, ok := snapstates[sn.InstanceName]
		if !ok {
			return snap.NotInstalledError{Snap: sn.InstanceName}
		}

		// default to existing cohort key if we don't have a provided one
		if sn.RevOpts.CohortKey == "" && !sn.RevOpts.LeaveCohort {
			sn.RevOpts.CohortKey = snapst.CohortKey
		}

		sn.RevOpts.Channel, err = resolveChannel(sn.InstanceName, snapst.TrackingChannel, sn.RevOpts.Channel, opts.DeviceCtx)
		if err != nil {
			return err
		}

		// default to tracking the already tracked channel, if we don't have a
		// provided one
		if sn.RevOpts.Channel == "" {
			sn.RevOpts.Channel = snapst.TrackingChannel
		}

		updates[sn.InstanceName] = sn
	}

	return nil
}

func filterHeldSnapsInSummary(st *state.State, summary *UpdateSummary, isAutoRefresh bool) error {
	holdLevel := HoldGeneral
	if isAutoRefresh {
		holdLevel = HoldAutoRefresh
	}

	heldSnaps, err := HeldSnaps(st, holdLevel)
	if err != nil {
		return err
	}

	summary.filter(func(t target) (bool, error) {
		_, ok := heldSnaps[t.info.InstanceName()]
		return !ok, nil
	})

	return nil
}

func refreshCandidatesV2(ctx context.Context, st *state.State, requested map[string]StoreUpdate, user *auth.UserState, refreshOpts *store.RefreshOptions, opts Options) (UpdateSummary, error) {
	// initialize options before using
	refreshOpts, err := refreshOptions(st, refreshOpts)
	if err != nil {
		return UpdateSummary{}, err
	}

	summary, err := refreshCandidatesCoreV2(ctx, st, requested, user, refreshOpts, opts)
	if err != nil {
		return UpdateSummary{}, err
	}

	if !refreshOpts.Scheduled {
		// not an auto-refresh, just return what we got
		return summary, nil
	}

	var oldHints map[string]*refreshCandidate
	if err := st.Get("refresh-candidates", &oldHints); err != nil {
		if errors.Is(err, &state.NoStateError{}) {
			// do nothing
			return summary, nil
		}

		return UpdateSummary{}, fmt.Errorf("cannot get refresh-candidates: %v", err)
	}

	missingRequests := make(map[string]StoreUpdate)
	for name, hint := range oldHints {
		if !hint.Monitored {
			continue
		}
		hasUpdate := false
		for _, update := range summary.Targets {
			if update.info.InstanceName() == name {
				hasUpdate = true
				break
			}
		}
		if hasUpdate {
			continue
		}

		req, ok := requested[name]
		if !ok {
			if !summary.RefreshAll {
				continue
			}
			req = StoreUpdate{InstanceName: name}
		}

		missingRequests[name] = req
	}

	if len(missingRequests) > 0 {
		if err := validateAndInitStoreUpdates(st, missingRequests, opts); err != nil {
			return UpdateSummary{}, err
		}

		// mimic manual refresh to avoid throttling.
		// context: snaps may be throttled by the store to balance load
		// and therefore may not always receive an update (even if one was
		// returned before). forcing a manual refresh should be fine since
		// we already started a pre-download for this snap, so no extra
		// load is being exerted on the store.
		refreshOpts.Scheduled = false
		extraSummary, err := refreshCandidatesCoreV2(ctx, st, missingRequests, user, refreshOpts, opts)
		if err != nil {
			return UpdateSummary{}, err
		}
		summary.Targets = append(summary.Targets, extraSummary.Targets...)
	}

	return summary, nil
}

func refreshCandidatesCoreV2(ctx context.Context, st *state.State, requested map[string]StoreUpdate, user *auth.UserState, refreshOpts *store.RefreshOptions, opts Options) (UpdateSummary, error) {
	if refreshOpts == nil {
		return UpdateSummary{}, fmt.Errorf("internal error: opts cannot be nil")
	}

	snapStates, err := All(st)
	if err != nil {
		return UpdateSummary{}, err
	}

	// check if we have this name at all
	for name := range requested {
		if _, ok := snapStates[name]; !ok {
			return UpdateSummary{}, snap.NotInstalledError{Snap: name}
		}
	}

	var fallbackID int
	// normalize fallback user
	if !user.HasStoreAuth() {
		user = nil
	} else {
		fallbackID = user.ID
	}

	actionsByUserID := make(map[int][]*store.SnapAction)

	// create a closure that will lazily load the enforced validation sets if
	// any of the targets require them
	var vsets *snapasserts.ValidationSets
	enforcedSets := func() (*snapasserts.ValidationSets, error) {
		if vsets != nil {
			return vsets, nil
		}

		var err error
		vsets, err = EnforcedValidationSets(st)
		if err != nil {
			return nil, err
		}

		return vsets, nil
	}

	refreshAll := len(requested) == 0

	// some snaps might have been requested to be updated but didn't get
	// updated, either because we detected that the requested/required revision
	// is already installed, or the store reported that there was no update
	// available. in either case, we need to keep track of these, since we still
	// might need to change the channel, cohort key, or validation set
	// enforcement.
	notUpdated := make(map[*SnapState]RevisionOptions)

	// some snaps will have a local revision that is the same as the requested
	// revision, we don't need to reach out to the store for these. keep track
	// of them so we can handle them differently.
	hasLocalRevision := make(map[*SnapState]RevisionOptions)

	addCand := func(installed *store.CurrentSnap, snapst *SnapState) error {
		// FIXME: snaps that are not active are skipped for now
		//        until we know what we want to do
		if !snapst.Active {
			return nil
		}

		if refreshAll && snapst.DevMode {
			// no auto-refresh for devmode
			return nil
		}

		req, ok := requested[installed.InstanceName]

		// if we're not refreshing all snaps, ignore anything that wasn't in the
		// refresh request
		if !refreshAll && !ok {
			return nil
		}

		// default the channel and cohort key to the existing values, this will
		// happen when refreshing all snaps
		if !ok {
			req.RevOpts.Channel = snapst.TrackingChannel
			req.RevOpts.CohortKey = snapst.CohortKey
		}

		if !req.RevOpts.Revision.Unset() && snapst.LastIndex(req.RevOpts.Revision) != -1 {
			hasLocalRevision[snapst] = req.RevOpts
			return nil
		}

		action := &store.SnapAction{
			Action:       "refresh",
			SnapID:       installed.SnapID,
			InstanceName: installed.InstanceName,
		}

		// if we are expecting only one snap to be updated, we respect the flag
		// that was passed in. this maintains the existing behavior of Update vs
		// UpdateMany.
		ignoreValidation := snapst.IgnoreValidation
		if opts.ExpectOneSnap {
			ignoreValidation = opts.Flags.IgnoreValidation
		}

		// TODO: this is silly, but it matches how we currently send these flags
		// now. we should probably just default to sending enforce, but that
		// would require updating a good number of tests. good candidate for a
		// follow-up PR.
		if opts.ExpectOneSnap {
			if opts.Flags.IgnoreValidation {
				action.Flags = store.SnapActionIgnoreValidation
			} else if req.RevOpts.Revision.Unset() {
				action.Flags = store.SnapActionEnforceValidation
			}
		}

		if err := completeStoreAction(action, req.RevOpts, ignoreValidation, enforcedSets); err != nil {
			return err
		}

		// if we already have the requested revision installed, we don't need to
		// consider this snap
		if !action.Revision.Unset() && action.Revision == installed.Revision {
			notUpdated[snapst] = req.RevOpts
			return nil
		}

		if !action.Revision.Unset() {
			// ignore cohort if revision is specified
			installed.CohortKey = ""
		}

		// only enforce refresh block if we are refreshing everything
		if refreshAll {
			installed.Block = snapst.Block()
		}

		userID := snapst.UserID
		if userID == 0 {
			userID = fallbackID
		}
		actionsByUserID[userID] = append(actionsByUserID[userID], action)
		return nil
	}

	// we also need to consider local revisions if the caller requested we
	// ammend existing installations
	if opts.Flags.Amend {
		for _, snapst := range snapStates {
			req, ok := requested[snapst.InstanceName()]

			// if we're not refreshing all snaps, ignore anything that wasn't in the
			// refresh request
			if !refreshAll && !ok {
				continue
			}

			// default the channel and cohort key to the existing values, this will
			// happen when refreshing all snaps
			if !ok {
				req.RevOpts.Channel = snapst.TrackingChannel
				req.RevOpts.CohortKey = snapst.CohortKey
			}

			info, err := snapst.CurrentInfo()
			if err != nil {
				return UpdateSummary{}, err
			}

			if info.SnapID != "" {
				continue
			}

			action := &store.SnapAction{
				Action:       "install",
				InstanceName: info.InstanceName(),
				Epoch:        info.Epoch,

				// TODO: updates default to enforcing validation sets, but i feel
				// that this flag should default to being set during installs too?
				Flags: store.SnapActionEnforceValidation,
			}

			ignoreValidation := snapst.IgnoreValidation
			if opts.ExpectOneSnap {
				ignoreValidation = opts.Flags.IgnoreValidation
			}

			if err := completeStoreAction(action, req.RevOpts, ignoreValidation, enforcedSets); err != nil {
				return UpdateSummary{}, err
			}

			userID := snapst.UserID
			if userID == 0 {
				userID = fallbackID
			}
			actionsByUserID[userID] = append(actionsByUserID[userID], action)
		}
	}

	names := make([]string, 0, len(requested))
	for _, sn := range requested {
		names = append(names, sn.InstanceName)
	}

	holds, err := SnapHolds(st, names)
	if err != nil {
		return UpdateSummary{}, err
	}

	// determine current snaps and collect candidates for refresh
	curSnaps, err := collectCurrentSnaps(snapStates, holds, addCand)
	if err != nil {
		return UpdateSummary{}, err
	}

	actionsForUser := make(map[*auth.UserState][]*store.SnapAction, len(actionsByUserID))
	noUserActions := actionsByUserID[0]
	for userID, actions := range actionsByUserID {
		if userID == 0 {
			continue
		}
		u, err := userFromUserID(st, userID, 0)
		if err != nil {
			return UpdateSummary{}, err
		}
		if u.HasStoreAuth() {
			actionsForUser[u] = actions
		} else {
			noUserActions = append(noUserActions, actions...)
		}
	}
	// coalesce if possible
	if len(noUserActions) != 0 {
		if len(actionsForUser) == 0 {
			actionsForUser[nil] = noUserActions
		} else {
			// coalesce no user actions with one other user's
			for u1, actions := range actionsForUser {
				actionsForUser[u1] = append(actions, noUserActions...)
				break
			}
		}
	}

	sto := Store(st, opts.DeviceCtx)

	var sars []store.SnapActionResult
	refreshErrors := make(map[string]error)
	for u, actions := range actionsForUser {
		st.Unlock()
		perUserSars, _, err := sto.SnapAction(ctx, curSnaps, actions, nil, u, refreshOpts)
		st.Lock()

		if err != nil {
			saErr, ok := err.(*store.SnapActionError)
			if !ok {
				return UpdateSummary{}, err
			}

			// save these, since we need to check later which snaps we were
			// requested to update but didn't get updated
			for name, e := range saErr.Refresh {
				refreshErrors[name] = e
			}

			logger.Noticef("%v", saErr)
		}

		sars = append(sars, perUserSars...)
	}

	channelAndCohort := func(instanceName string) (string, string, error) {
		// if we are refreshing all snaps, then the caller cannot specify new a
		// channel/cohort, so we must use the existing ones
		if refreshAll {
			snapst, ok := snapStates[instanceName]
			if !ok {
				return "", "", fmt.Errorf("internal error: missing snap state for %q", instanceName)
			}
			return snapst.TrackingChannel, snapst.CohortKey, nil
		}

		req, ok := requested[instanceName]
		if !ok {
			return "", "", fmt.Errorf("unsolicited snap update: %s", instanceName)
		}

		return req.RevOpts.Channel, req.RevOpts.CohortKey, nil
	}

	var targets []target
	for _, sar := range sars {
		channel, cohort, err := channelAndCohort(sar.InstanceName())
		if err != nil {
			return UpdateSummary{}, err
		}

		snapst, ok := snapStates[sar.InstanceName()]
		if !ok {
			return UpdateSummary{}, fmt.Errorf("internal error: missing snap state for %q", sar.InstanceName())
		}

		targets = append(targets, target{
			info:   sar.Info,
			snapst: *snapst,
			setup: SnapSetup{
				DownloadInfo: &sar.DownloadInfo,
				Channel:      channel,
				CohortKey:    cohort,
			},
			components: nil, // TODO: fill this out from the already installed components from snapst
		})
	}

	for snapst, revOpts := range hasLocalRevision {
		info, err := readInfo(snapst.InstanceName(), snapst.CurrentSideInfo(), errorOnBroken)
		if err != nil {
			return UpdateSummary{}, err
		}

		targets = append(targets, target{
			info:   info,
			snapst: *snapst,
			setup: SnapSetup{
				Channel:   revOpts.Channel,
				CohortKey: revOpts.CohortKey,
				SnapPath:  info.MountFile(),
			},
			components: nil,
		})
	}

	for name, err := range refreshErrors {
		if errors.Is(err, store.ErrNoUpdateAvailable) {
			notUpdated[snapStates[name]] = requested[name].RevOpts
		}
	}

	return UpdateSummary{
		Requested:          names,
		RefreshAll:         refreshAll,
		Targets:            targets,
		UpdateNotAvailable: notUpdated,
	}, nil
}

// TODO: would really like for this to take an UpdateSummary as a param, but it
// doesn't quite work for all use cases
func doUpdateV2(st *state.State, requested []string, snapsups []SnapSetup, snapstates map[string]SnapState, components map[string][]ComponentSetup, opts Options) ([]string, *UpdateTaskSets, error) {
	if len(snapsups) != len(snapstates) {
		return nil, nil, fmt.Errorf("internal error: snapstates and snapsups must have the same length")
	}

	if components == nil {
		components = make(map[string][]ComponentSetup)
	}

	var installTasksets []*state.TaskSet
	var preDlTasksets []*state.TaskSet

	refreshAll := len(requested) == 0

	var nameSet map[string]bool
	if len(requested) != 0 {
		nameSet = make(map[string]bool, len(requested))
		for _, name := range requested {
			nameSet[name] = true
		}
	}

	updateNames := make([]string, 0, len(snapsups))
	for _, up := range snapsups {
		updateNames = append(updateNames, up.InstanceName())
	}

	newAutoAliases, mustPruneAutoAliases, transferTargets, err := autoAliasesUpdateV2(st, requested, updateNames)
	if err != nil {
		return nil, nil, err
	}

	reportUpdated := make(map[string]bool, len(snapsups))
	var pruningAutoAliasesTs *state.TaskSet

	if len(mustPruneAutoAliases) != 0 {
		var err error
		pruningAutoAliasesTs, err = applyAutoAliasesDelta(st, mustPruneAutoAliases, "prune", refreshAll, opts.FromChange, func(snapName string, _ *state.TaskSet) {
			if nameSet[snapName] {
				reportUpdated[snapName] = true
			}
		})
		if err != nil {
			return nil, nil, err
		}
		installTasksets = append(installTasksets, pruningAutoAliasesTs)
	}

	// wait for the auto-alias prune tasks as needed
	scheduleUpdate := func(snapName string, ts *state.TaskSet) {
		if pruningAutoAliasesTs != nil && (mustPruneAutoAliases[snapName] != nil || transferTargets[snapName]) {
			ts.WaitAll(pruningAutoAliasesTs)
		}
		reportUpdated[snapName] = true
	}

	// first snapd, core, kernel, bases, then rest
	sort.SliceStable(snapsups, func(i, j int) bool {
		return snapsups[i].Type.SortsBefore(snapsups[j].Type)
	})

	if opts.Flags.Transaction == client.TransactionAllSnaps && opts.Flags.Lane == 0 {
		opts.Flags.Lane = st.NewLane()
	}

	// updates is sorted by kind so this will process first core
	// and bases and then other snaps
	for _, snapsup := range snapsups {
		snapst, ok := snapstates[snapsup.InstanceName()]
		if !ok {
			return nil, nil, fmt.Errorf("internal error: missing snap state for %q", snapsup.InstanceName())
		}

		compsups := components[snapsup.InstanceName()]

		// Do not set any default restart boundaries, we do it when we have access to all
		// the task-sets in preparation for single-reboot.
		ts, err := doInstall(st, &snapst, snapsup, compsups, noRestartBoundaries, opts.FromChange, inUseFor(opts.DeviceCtx))
		if err != nil {
			if errors.Is(err, &timedBusySnapError{}) && ts != nil {
				// snap is busy and pre-download tasks were made for it
				ts.JoinLane(st.NewLane())
				preDlTasksets = append(preDlTasksets, ts)
				continue
			}

			if refreshAll {
				logger.Noticef("cannot refresh snap %q: %v", snapsup.InstanceName(), err)
				continue
			}
			return nil, nil, err
		}

		ts.JoinLane(generateLane(st, opts))

		scheduleUpdate(snapsup.InstanceName(), ts)
		installTasksets = append(installTasksets, ts)
	}

	// Make sure each of them are marked with default restart-boundaries to maintain the previous
	// reboot-behaviour prior to new restart logic.
	if err := arrangeSnapTaskSetsLinkageAndRestart(st, nil, installTasksets); err != nil {
		return nil, nil, err
	}

	if len(newAutoAliases) != 0 {
		addAutoAliasesTs, err := applyAutoAliasesDelta(st, newAutoAliases, "refresh", refreshAll, opts.FromChange, scheduleUpdate)
		if err != nil {
			return nil, nil, err
		}
		installTasksets = append(installTasksets, addAutoAliasesTs)
	}

	updated := make([]string, 0, len(reportUpdated))
	for name := range reportUpdated {
		updated = append(updated, name)
	}

	updateTss := &UpdateTaskSets{
		Refresh:     installTasksets,
		PreDownload: preDlTasksets,
	}

	return updated, updateTss, nil
}

func autoAliasesUpdateV2(st *state.State, requestedUpdates []string, updateNames []string) (changed map[string][]string, mustPrune map[string][]string, transferTargets map[string]bool, err error) {
	changed, dropped, err := autoAliasesDelta(st, nil)
	if err != nil {
		if len(requestedUpdates) != 0 {
			// not "refresh all", error
			return nil, nil, nil, err
		}
		// log and continue
		logger.Noticef("cannot find the delta for automatic aliases for some snaps: %v", err)
	}

	refreshAll := len(requestedUpdates) == 0

	// dropped alias -> snapName
	droppedAliases := make(map[string][]string, len(dropped))
	for instanceName, aliases := range dropped {
		for _, alias := range aliases {
			droppedAliases[alias] = append(droppedAliases[alias], instanceName)
		}
	}

	// filter changed considering only names if set:
	// we add auto-aliases only for mentioned snaps
	if !refreshAll && len(changed) != 0 {
		filteredChanged := make(map[string][]string, len(changed))
		for _, name := range requestedUpdates {
			if changed[name] != nil {
				filteredChanged[name] = changed[name]
			}
		}
		changed = filteredChanged
	}

	// mark snaps that are sources or target of transfers
	transferSources := make(map[string]bool, len(dropped))
	transferTargets = make(map[string]bool, len(changed))
	for instanceName, aliases := range changed {
		for _, alias := range aliases {
			if sources := droppedAliases[alias]; len(sources) != 0 {
				transferTargets[instanceName] = true
				for _, source := range sources {
					transferSources[source] = true
				}
			}
		}
	}

	// snaps with updates
	updating := make(map[string]bool, len(updateNames))
	for _, name := range updateNames {
		updating[name] = true
	}

	// add explicitly auto-aliases only for snaps that are not updated
	for instanceName := range changed {
		if updating[instanceName] {
			delete(changed, instanceName)
		}
	}

	// prune explicitly auto-aliases only for snaps that are mentioned
	// and not updated OR the source of transfers
	mustPrune = make(map[string][]string, len(dropped))
	for instanceName := range transferSources {
		mustPrune[instanceName] = dropped[instanceName]
	}
	if refreshAll {
		for instanceName, aliases := range dropped {
			if !updating[instanceName] {
				mustPrune[instanceName] = aliases
			}
		}
	} else {
		for _, name := range requestedUpdates {
			if !updating[name] && dropped[name] != nil {
				mustPrune[name] = dropped[name]
			}
		}
	}

	return changed, mustPrune, transferTargets, nil
}

// InstallOne is a convenience wrapper for InstallWithGoal that ensures that a
// single snap is being installed and unwraps the results to return a single
// snap.Info and state.TaskSet. If the InstallGoal does not request to install
// exactly one snap, an error is returned.
func InstallOne(ctx context.Context, st *state.State, goal InstallGoal, opts Options) (*snap.Info, *state.TaskSet, error) {
	opts.ExpectOneSnap = true

	infos, tasksets, err := InstallWithGoal(ctx, st, goal, opts)
	if err != nil {
		return nil, nil, err
	}

	// this case is unexpected since InstallWithGoal verifies that we are
	// operating on exactly one target
	if len(infos) != 1 || len(tasksets) != 1 {
		return nil, nil, errors.New("internal error: expected exactly one snap and task set")
	}

	return infos[0], tasksets[0], nil
}

// InstallWithGoal installs the snap/set of snaps specified by the given
// InstallGoal.
//
// The InstallGoal controls what snaps should be installed and where to source the
// snaps from. The Options struct contains optional parameters that apply to the
// installation operation.
//
// A slice of snap.Info structs is returned for each snap that is being
// installed along with a slice of state.TaskSet structs that represent the
// tasks that are part of the installation operation for each snap.
//
// TODO: rename this to Install once the API is settled, and we can rename or
// remove the old Install function.
func InstallWithGoal(ctx context.Context, st *state.State, goal InstallGoal, opts Options) ([]*snap.Info, []*state.TaskSet, error) {
	// can only specify a lane when running multiple operations transactionally
	if opts.Flags.Transaction != client.TransactionAllSnaps && opts.Flags.Lane != 0 {
		return nil, nil, errors.New("cannot specify a lane without setting transaction to \"all-snaps\"")
	}

	if opts.Flags.Transaction == client.TransactionAllSnaps && opts.Flags.Lane == 0 {
		opts.Flags.Lane = st.NewLane()
	}

	if err := setDefaultSnapstateOptions(st, &opts); err != nil {
		return nil, nil, err
	}

	targets, err := goal.toInstall(ctx, st, opts)
	if err != nil {
		return nil, nil, err
	}

	// this might be checked earlier in the implementation of InstallGoal, but
	// we should check it here as well to be safe
	if opts.ExpectOneSnap && len(targets) != 1 {
		return nil, nil, ErrExpectedOneSnap
	}

	for _, t := range targets {
		// sort the components by name to ensure we always install components in the
		// same order
		sort.Slice(t.components, func(i, j int) bool {
			return t.components[i].info.Component.String() < t.components[j].info.Component.String()
		})
	}

	installInfos := make([]minimalInstallInfo, 0, len(targets))
	for _, t := range targets {
		installInfos = append(installInfos, installSnapInfo{t.info})
	}

	// note: this has the potential to reach out to the store, depending on
	// which prereq tracker is being used.
	if err = checkDiskSpace(st, "install", installInfos, opts.UserID, opts.PrereqTracker); err != nil {
		return nil, nil, err
	}

	tasksets := make([]*state.TaskSet, 0, len(targets))
	infos := make([]*snap.Info, 0, len(targets))
	for _, t := range targets {
		if t.setup.SnapPath != "" && t.setup.DownloadInfo != nil {
			return nil, nil, errors.New("internal error: target cannot specify both a path and a download info")
		}

		if opts.Flags.RequireTypeBase && t.info.Type() != snap.TypeBase && t.info.Type() != snap.TypeOS {
			return nil, nil, fmt.Errorf("unexpected snap type %q, instead of 'base'", t.info.Type())
		}

		opts.PrereqTracker.Add(t.info)

		snapsup, compsups, err := t.setups(st, opts)
		if err != nil {
			return nil, nil, err
		}

		var instFlags int
		if opts.Flags.SkipConfigure {
			instFlags |= skipConfigure
		}

		ts, err := doInstall(st, &t.snapst, snapsup, compsups, instFlags, opts.FromChange, inUseFor(opts.DeviceCtx))
		if err != nil {
			return nil, nil, err
		}

		ts.JoinLane(generateLane(st, opts))

		tasksets = append(tasksets, ts)
		infos = append(infos, t.info)
	}

	return infos, tasksets, nil
}

func UpdateOne(ctx context.Context, st *state.State, goal UpdateGoal, filter updateFilter, opts Options) (*state.TaskSet, error) {
	opts.ExpectOneSnap = true

	updated, uts, err := UpdateWithGoal(ctx, st, goal, filter, opts)
	if err != nil {
		return nil, err
	}

	if len(updated) != 1 || len(uts.Refresh) != 1 {
		return nil, errors.New("internal error: expected exactly one snap to be updated")
	}

	return uts.Refresh[0], nil
}

func UpdateWithGoal(ctx context.Context, st *state.State, goal UpdateGoal, filter updateFilter, opts Options) ([]string, *UpdateTaskSets, error) {
	if err := setDefaultSnapstateOptions(st, &opts); err != nil {
		return nil, nil, err
	}

	if opts.ExpectOneSnap && opts.Flags.IsAutoRefresh {
		return nil, nil, errors.New("internal error: auto-refresh is not supported when updating a single snap")
	}

	// can only specify a lane when running multiple operations transactionally
	if opts.Flags.Transaction != client.TransactionAllSnaps && opts.Flags.Lane != 0 {
		return nil, nil, errors.New("cannot specify a lane without setting transaction to \"all-snaps\"")
	}

	if opts.Flags.Transaction == "" {
		opts.Flags.Lane = st.NewLane()
	}

	summary, err := goal.toUpdate(ctx, st, opts)
	if err != nil {
		return nil, nil, err
	}

	if opts.ExpectOneSnap && len(summary.Targets)+len(summary.UpdateNotAvailable) != 1 {
		return nil, nil, ErrExpectedOneSnap
	}

	if filter != nil {
		summary.filter(func(t target) (bool, error) {
			return filter(t.info, &t.snapst), nil
		})
	}

	if err := filterHeldSnapsInSummary(st, &summary, opts.Flags.IsAutoRefresh); err != nil {
		return nil, nil, err
	}

	// save the candidates so the auto-refresh can be continued if it's inhibited
	// by a running snap.
	if opts.Flags.IsAutoRefresh {
		hints, err := refreshHintsFromCandidates(st, summary, opts.DeviceCtx)
		if err != nil {
			return nil, nil, err
		}

		updateRefreshCandidates(st, hints, summary.Requested)
	}

	// validate that the snaps can be refreshed. if we are refreshing all snaps,
	// then we filter out the snaps that cannot be validated and log them
	if err := validateAndFilterSummaryRefreshes(st, &summary, opts); err != nil {
		return nil, nil, err
	}

	installInfos := make([]minimalInstallInfo, 0, len(summary.Targets))
	for _, t := range summary.Targets {
		installInfos = append(installInfos, installSnapInfo{t.info})
	}

	// note: this has the potential to reach out to the store, depending on
	// which prereq tracker is being used.
	if err := checkDiskSpace(st, "refresh", installInfos, opts.UserID, opts.PrereqTracker); err != nil {
		return nil, nil, err
	}

	snapsups := make([]SnapSetup, 0, len(summary.Targets))
	components := make(map[string][]ComponentSetup, len(summary.Targets))
	snapstates := make(map[string]SnapState, len(summary.Targets))
	for _, t := range summary.Targets {
		snapsup, compsups, err := t.setups(st, opts)
		if err != nil {
			if !summary.RefreshAll {
				return nil, nil, err
			}

			logger.Noticef("cannot refresh snap %q: %v", t.info.InstanceName(), err)
			continue
		}

		snapsups = append(snapsups, snapsup)
		components[t.snapst.InstanceName()] = compsups
		snapstates[t.snapst.InstanceName()] = t.snapst
	}

	// TODO: ignore split refresh for now, come back later
	updated, uts, err := doUpdateV2(st, summary.Requested, snapsups, snapstates, components, opts)
	if err != nil {
		return nil, nil, err
	}

	// some snaps might not have had a revision available to update to, but we
	// still need to update the channel, cohort key, or validation set
	// enforcement
	for snapst, up := range summary.UpdateNotAvailable {
		tss, err := switchSnapMetadataTasks(st, snapst, up, opts)
		if err != nil {
			return nil, nil, err
		}

		if len(tss) > 0 {
			for _, refreshTs := range uts.Refresh {
				for _, ts := range tss {
					ts.WaitAll(refreshTs)
				}
			}
			updated = append(updated, snapst.InstanceName())
			uts.Refresh = append(uts.Refresh, tss...)
		}
	}

	// ideally we wouldn't use this error type here, but the current
	// implementations share this error type for both path and store
	// installations
	if opts.ExpectOneSnap && len(uts.Refresh) == 0 {
		return nil, nil, store.ErrNoUpdateAvailable
	}

	// if there are only pre-downloads, don't add a check-rerefresh task
	if len(uts.Refresh) > 0 {
		uts.Refresh = finalizeUpdate(st, uts.Refresh, len(summary.Targets) > 0, updated, nil, opts.UserID, &opts.Flags)
	}

	// if we're only updating one snap, flatten everything into one task set
	if opts.ExpectOneSnap {
		flat := state.NewTaskSet()
		for _, ts := range uts.Refresh {
			// The tasksets we get from "doUpdate" contain important "TaskEdge"
			// information that is needed for "Remodel". To preserve those we
			// need to use "AddAllWithEdges()".
			if err := flat.AddAllWithEdges(ts); err != nil {
				return nil, nil, err
			}
		}
		uts.Refresh = []*state.TaskSet{flat}
	}

	return updated, uts, nil
}

func switchSnapMetadataTasks(st *state.State, snapst *SnapState, revOpts RevisionOptions, opts Options) ([]*state.TaskSet, error) {
	switchChannel := snapst.TrackingChannel != revOpts.Channel
	switchCohortKey := snapst.CohortKey != revOpts.CohortKey

	// we only toggle validation set enforcement if we are refreshing exactly
	// one snap
	toggleIgnoreValidation := (snapst.IgnoreValidation != opts.Flags.IgnoreValidation) && opts.ExpectOneSnap

	var tss []*state.TaskSet
	if switchChannel || switchCohortKey || toggleIgnoreValidation {
		if err := checkChangeConflictIgnoringOneChange(st, snapst.InstanceName(), nil, opts.FromChange); err != nil {
			return nil, err
		}

		snapsup := &SnapSetup{
			SideInfo:    snapst.CurrentSideInfo(),
			Flags:       snapst.ForSnapSetup(),
			InstanceKey: snapst.InstanceKey,
			Type:        snap.Type(snapst.SnapType),
			// no version info needed
			CohortKey: revOpts.CohortKey,
		}

		if switchChannel || switchCohortKey {
			// update the tracked channel and cohort
			snapsup.Channel = revOpts.Channel
			snapsup.CohortKey = revOpts.CohortKey
			// Update the current snap channel as well. This ensures that
			// the UI displays the right values.
			snapsup.SideInfo.Channel = revOpts.Channel

			summary := switchSummary(snapsup.InstanceName(), snapst.TrackingChannel, revOpts.Channel, snapst.CohortKey, revOpts.CohortKey)
			switchSnap := st.NewTask("switch-snap-channel", summary)
			switchSnap.Set("snap-setup", &snapsup)

			tss = append(tss, state.NewTaskSet(switchSnap))
		}

		if toggleIgnoreValidation {
			snapsup.IgnoreValidation = opts.Flags.IgnoreValidation
			toggle := st.NewTask("toggle-snap-flags", fmt.Sprintf(i18n.G("Toggle snap %q flags"), snapsup.InstanceName()))
			toggle.Set("snap-setup", &snapsup)

			toggleTs := state.NewTaskSet(toggle)
			for _, ts := range tss {
				toggleTs.WaitAll(ts)
			}

			tss = append(tss, toggleTs)
		}

		currentInfo, err := snapst.CurrentInfo()
		if err != nil {
			return nil, err
		}

		// if there isn't an update available, then we should still add the
		// current info to the prereq tracker. this is because we will not
		// return an error from this function, and the caller will assume
		// everything worked.
		addPrereq(opts.PrereqTracker, currentInfo)
	}

	lane := generateLane(st, opts)
	for _, ts := range tss {
		ts.JoinLane(lane)
	}

	return tss, nil
}

func validateAndFilterSummaryRefreshes(st *state.State, summary *UpdateSummary, opts Options) error {
	if ValidateRefreshes == nil || len(summary.Targets) == 0 || opts.Flags.IgnoreValidation {
		return nil
	}

	ignoreValidation := make(map[string]bool, len(summary.Targets))
	for _, t := range summary.Targets {
		if t.snapst.IgnoreValidation {
			ignoreValidation[t.info.InstanceName()] = true
		}
	}

	validated, err := ValidateRefreshes(st, summary.targetInfos(), ignoreValidation, opts.UserID, opts.DeviceCtx)
	if err != nil {
		if !summary.RefreshAll {
			return err
		}
		logger.Noticef("cannot refresh some snaps: %v", err)
	}

	validatedMap := make(map[string]bool, len(validated))
	for _, sn := range validated {
		validatedMap[sn.InstanceName()] = true
	}

	summary.filter(func(t target) (bool, error) {
		_, ok := validatedMap[t.info.InstanceName()]
		return ok, nil
	})

	return nil
}

func generateLane(st *state.State, opts Options) int {
	// If transactional, use a single lane for all snaps, so when
	// one fails the changes for all affected snaps will be
	// undone. Otherwise, have different lanes per snap so failures
	// only affect the culprit snap.
	switch opts.Flags.Transaction {
	case client.TransactionAllSnaps:
		return opts.Flags.Lane
	case client.TransactionPerSnap:
		return st.NewLane()
	}
	return opts.Flags.Lane
}

func setDefaultSnapstateOptions(st *state.State, opts *Options) error {
	var err error
	if opts.Seed {
		opts.DeviceCtx, err = DeviceCtxFromState(st, opts.DeviceCtx)
	} else {
		opts.DeviceCtx, err = DevicePastSeeding(st, opts.DeviceCtx)
	}

	if opts.PrereqTracker == nil {
		opts.PrereqTracker = snap.SimplePrereqTracker{}
	}
	return err
}

// pathInstallGoal represents a single snap to be installed from a path on disk.
type pathInstallGoal struct {
	// path is the path to the snap on disk.
	path string
	// instanceName is the name of the snap to install.
	instanceName string
	// revOpts contains options that apply to the installation of this snap.
	revOpts RevisionOptions
	// sideInfo contains extra information about the snap.
	sideInfo *snap.SideInfo
	// components is a mapping of component side infos to paths that should be
	// installed alongside this snap.
	components map[*snap.ComponentSideInfo]string
}

// PathInstallGoal creates a new InstallGoal to install a snap from a given from
// a path on disk. If instanceName is not provided, si.RealName will be used.
func PathInstallGoal(instanceName, path string, si *snap.SideInfo, components map[*snap.ComponentSideInfo]string, opts RevisionOptions) InstallGoal {
	return &pathInstallGoal{
		instanceName: instanceName,
		path:         path,
		revOpts:      opts,
		sideInfo:     si,
		components:   components,
	}
}

// toInstall returns the data needed to setup the snap from disk.
func (p *pathInstallGoal) toInstall(ctx context.Context, st *state.State, opts Options) ([]target, error) {
	si := p.sideInfo

	if si.RealName == "" {
		return nil, fmt.Errorf("internal error: snap name to install %q not provided", p.path)
	}

	if si.SnapID != "" {
		if si.Revision.Unset() {
			return nil, fmt.Errorf("internal error: snap id set to install %q but revision is unset", p.path)
		}
	}

	if p.instanceName == "" {
		p.instanceName = si.RealName
	}

	if err := snap.ValidateInstanceName(p.instanceName); err != nil {
		return nil, fmt.Errorf("invalid instance name: %v", err)
	}

	if err := validateRevisionOpts(&p.revOpts); err != nil {
		return nil, fmt.Errorf("invalid revision options for snap %q: %w", p.instanceName, err)
	}

	if !p.revOpts.Revision.Unset() && p.revOpts.Revision != si.Revision {
		return nil, fmt.Errorf("cannot install local snap %q: %v != %v (revision mismatch)", p.instanceName, p.revOpts.Revision, si.Revision)
	}

	info, err := validatedInfoFromPathAndSideInfo(p.instanceName, p.path, si)
	if err != nil {
		return nil, err
	}

	snapName, instanceKey := snap.SplitInstanceName(p.instanceName)
	if info.SnapName() != snapName {
		return nil, fmt.Errorf("cannot install snap %q, the name does not match the metadata %q", p.instanceName, info.SnapName())
	}
	info.InstanceKey = instanceKey

	var snapst SnapState
	if err := Get(st, p.instanceName, &snapst); err != nil && !errors.Is(err, state.ErrNoState) {
		return nil, err
	}

	var trackingChannel string
	if snapst.IsInstalled() {
		trackingChannel = snapst.TrackingChannel
	}

	channel, err := resolveChannel(p.instanceName, trackingChannel, p.revOpts.Channel, opts.DeviceCtx)
	if err != nil {
		return nil, err
	}

	comps, err := installableComponentsFromPaths(info, p.components)
	if err != nil {
		return nil, err
	}

	inst := target{
		setup: SnapSetup{
			SnapPath:  p.path,
			Channel:   channel,
			CohortKey: p.revOpts.CohortKey,
		},
		info:       info,
		snapst:     snapst,
		components: comps,
	}

	return []target{inst}, nil
}

func installableComponentsFromPaths(info *snap.Info, components map[*snap.ComponentSideInfo]string) ([]componentTarget, error) {
	installables := make([]componentTarget, 0, len(components))
	for csi, path := range components {
		compInfo, _, err := backend.OpenComponentFile(path, info, csi)
		if err != nil {
			return nil, err
		}

		installables = append(installables, componentTarget{
			setup: ComponentSetup{
				CompPath: path,
			},
			info: compInfo,
		})
	}

	return installables, nil
}
