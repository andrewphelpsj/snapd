// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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

package devicestate_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "gopkg.in/check.v1"
	"gopkg.in/tomb.v2"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/assertstest"
	"github.com/snapcore/snapd/asserts/snapasserts"
	"github.com/snapcore/snapd/boot"
	"github.com/snapcore/snapd/bootloader"
	"github.com/snapcore/snapd/bootloader/bootloadertest"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/gadget"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/overlord/assertstate"
	"github.com/snapcore/snapd/overlord/assertstate/assertstatetest"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/overlord/devicestate"
	"github.com/snapcore/snapd/overlord/devicestate/devicestatetest"
	"github.com/snapcore/snapd/overlord/install"
	"github.com/snapcore/snapd/overlord/restart"
	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/snapstate/sequence"
	"github.com/snapcore/snapd/overlord/snapstate/snapstatetest"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/release"
	"github.com/snapcore/snapd/secboot"
	"github.com/snapcore/snapd/seed"
	"github.com/snapcore/snapd/seed/seedtest"
	"github.com/snapcore/snapd/seed/seedwriter"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/naming"
	"github.com/snapcore/snapd/snap/snaptest"
	"github.com/snapcore/snapd/strutil"
	"github.com/snapcore/snapd/testutil"
)

type mockedSystemSeed struct {
	label string
	model *asserts.Model
	brand *asserts.Account
}

type deviceMgrSystemsBaseSuite struct {
	deviceMgrBaseSuite

	logbuf            *bytes.Buffer
	mockedSystemSeeds []mockedSystemSeed
	ss                *seedtest.SeedSnaps
	model             *asserts.Model
}

type deviceMgrSystemsSuite struct {
	deviceMgrSystemsBaseSuite
}

var _ = Suite(&deviceMgrSystemsSuite{})
var _ = Suite(&deviceMgrSystemsCreateSuite{})

func (s *deviceMgrSystemsBaseSuite) SetUpTest(c *C) {
	classic := false
	s.deviceMgrBaseSuite.setupBaseTest(c, classic)

	s.brands.Register("other-brand", brandPrivKey3, map[string]any{
		"display-name": "other publisher",
	})
	s.state.Lock()
	defer s.state.Unlock()
	s.ss = &seedtest.SeedSnaps{
		StoreSigning: s.storeSigning,
		Brands:       s.brands,
	}

	s.model = s.makeModelAssertionInState(c, "canonical", "pc-20", map[string]any{
		"architecture": "amd64",
		// UC20
		"grade": "dangerous",
		"base":  "core20",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel",
				"id":              s.ss.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]any{
				"name":            "pc",
				"id":              s.ss.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
			map[string]any{
				"name": "core20",
				"id":   s.ss.AssertedSnapID("core20"),
				"type": "base",
			},
			map[string]any{
				"name": "snapd",
				"id":   s.ss.AssertedSnapID("snapd"),
				"type": "snapd",
			},
		},
	})
	devicestatetest.SetDevice(s.state, &auth.DeviceState{
		Brand:  "canonical",
		Model:  "pc-20",
		Serial: "serialserialserial",
	})
	assertstest.AddMany(s.storeSigning.Database, s.brands.AccountsAndKeys("my-brand")...)
	assertstest.AddMany(s.storeSigning.Database, s.brands.AccountsAndKeys("other-brand")...)

	// all tests should be in run mode by default, if they need to be in
	// different modes they should set that individually
	devicestate.SetSystemMode(s.mgr, "run")

	// state after mark-seeded ran
	modeenv := boot.Modeenv{
		Mode:           "run",
		RecoverySystem: "",

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	}
	err := modeenv.WriteTo("")
	c.Assert(err, IsNil)

	s.state.Set("seeded", true)

	logbuf, restore := logger.MockLogger()
	s.logbuf = logbuf
	s.AddCleanup(restore)

	nopHandler := func(task *state.Task, _ *tomb.Tomb) error { return nil }
	s.o.TaskRunner().AddHandler("fake-download", nopHandler, nil)
	s.o.TaskRunner().AddHandler("fake-validate", nopHandler, nil)
}

func (s *deviceMgrSystemsSuite) SetUpTest(c *C) {
	s.deviceMgrSystemsBaseSuite.SetUpTest(c)

	// now create a minimal uc20 seed dir with snaps/assertions
	seed20 := &seedtest.TestingSeed20{
		SeedSnaps: *s.ss,
		SeedDir:   dirs.SnapSeedDir,
	}

	restore := seed.MockTrusted(s.storeSigning.Trusted)
	s.AddCleanup(restore)

	myBrandAcc := s.brands.Account("my-brand")
	otherBrandAcc := s.brands.Account("other-brand")

	// add essential snaps
	seed20.MakeAssertedSnap(c, "name: snapd\nversion: 1\ntype: snapd", nil, snap.R(1), "canonical", seed20.StoreSigning.Database)
	seed20.MakeAssertedSnap(c, "name: pc\nversion: 1\ntype: gadget\nbase: core20", nil, snap.R(1), "canonical", seed20.StoreSigning.Database)
	seed20.MakeAssertedSnap(c, "name: pc-kernel\nversion: 1\ntype: kernel", nil, snap.R(1), "canonical", seed20.StoreSigning.Database)
	seed20.MakeAssertedSnap(c, "name: core20\nversion: 1\ntype: base", nil, snap.R(1), "canonical", seed20.StoreSigning.Database)

	model1 := seed20.MakeSeed(c, "20191119", "my-brand", "my-model", map[string]any{
		"display-name": "my fancy model",
		"architecture": "amd64",
		"base":         "core20",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel",
				"id":              seed20.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]any{
				"name":            "pc",
				"id":              seed20.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			}},
	}, nil)
	model2 := seed20.MakeSeed(c, "20200318", "my-brand", "my-model-2", map[string]any{
		"display-name": "same brand different model",
		"architecture": "amd64",
		"base":         "core20",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel",
				"id":              seed20.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]any{
				"name":            "pc",
				"id":              seed20.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			}},
	}, nil)
	model3 := seed20.MakeSeed(c, "other-20200318", "other-brand", "other-model", map[string]any{
		"display-name": "different brand different model",
		"architecture": "amd64",
		"base":         "core20",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel",
				"id":              seed20.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]any{
				"name":            "pc",
				"id":              seed20.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			}},
	}, nil)

	s.mockedSystemSeeds = []mockedSystemSeed{{
		label: "20191119",
		model: model1,
		brand: myBrandAcc,
	}, {
		label: "20200318",
		model: model2,
		brand: myBrandAcc,
	}, {
		label: "other-20200318",
		model: model3,
		brand: otherBrandAcc,
	}}
}

func (s *deviceMgrSystemsSuite) TestListNoSystems(c *C) {
	dirs.SetRootDir(c.MkDir())

	systems, err := s.mgr.Systems()
	c.Assert(err, Equals, devicestate.ErrNoSystems)
	c.Assert(systems, HasLen, 0)

	err = os.MkdirAll(filepath.Join(dirs.SnapSeedDir, "systems"), 0755)
	c.Assert(err, IsNil)

	systems, err = s.mgr.Systems()
	c.Assert(err, Equals, devicestate.ErrNoSystems)
	c.Assert(systems, HasLen, 0)
}

func (s *deviceMgrSystemsSuite) TestListSystemsNotPossible(c *C) {
	if os.Geteuid() == 0 {
		c.Skip("this test cannot run as root")
	}
	err := os.Chmod(filepath.Join(dirs.SnapSeedDir, "systems"), 0000)
	c.Assert(err, IsNil)
	defer os.Chmod(filepath.Join(dirs.SnapSeedDir, "systems"), 0755)

	// stdlib swallows up the errors when opening the target directory
	systems, err := s.mgr.Systems()
	c.Assert(err, Equals, devicestate.ErrNoSystems)
	c.Assert(systems, HasLen, 0)
}

// TODO:UC20 update once we can list actions
var defaultSystemActions []devicestate.SystemAction = []devicestate.SystemAction{
	{Title: "Install", Mode: "install"},
	{Title: "Recover", Mode: "recover"},
	{Title: "Factory reset", Mode: "factory-reset"},
}

var currentSystemActions []devicestate.SystemAction = []devicestate.SystemAction{
	{Title: "Reinstall", Mode: "install"},
	{Title: "Recover", Mode: "recover"},
	{Title: "Factory reset", Mode: "factory-reset"},
	{Title: "Run normally", Mode: "run"},
}

var recoverySystemActions []devicestate.SystemAction = []devicestate.SystemAction{
	{Title: "Reinstall", Mode: "install"},
	{Title: "Factory reset", Mode: "factory-reset"},
	{Title: "Run normally", Mode: "run"},
}

func (s *deviceMgrSystemsSuite) TestListSeedSystemsNoCurrent(c *C) {
	systems, err := s.mgr.Systems()
	c.Assert(err, IsNil)
	c.Assert(systems, HasLen, 3)
	c.Check(systems, DeepEquals, []*devicestate.System{{
		Current: false,
		Label:   s.mockedSystemSeeds[0].label,
		Model:   s.mockedSystemSeeds[0].model,
		Brand:   s.mockedSystemSeeds[0].brand,
		Actions: defaultSystemActions,
	}, {
		Current: false,
		Label:   s.mockedSystemSeeds[1].label,
		Model:   s.mockedSystemSeeds[1].model,
		Brand:   s.mockedSystemSeeds[1].brand,
		Actions: defaultSystemActions,
	}, {
		Current: false,
		Label:   s.mockedSystemSeeds[2].label,
		Model:   s.mockedSystemSeeds[2].model,
		Brand:   s.mockedSystemSeeds[2].brand,
		Actions: defaultSystemActions,
	}})
}

func (s *deviceMgrSystemsSuite) TestListSeedSystemsDefaultRecoverySystem(c *C) {
	s.state.Lock()
	s.state.Set("default-recovery-system", devicestate.DefaultRecoverySystem{
		System:   s.mockedSystemSeeds[0].label,
		Model:    s.mockedSystemSeeds[0].model.Model(),
		BrandID:  s.mockedSystemSeeds[0].model.BrandID(),
		Revision: s.mockedSystemSeeds[0].model.Revision(),
	})
	s.state.Unlock()

	systems, err := s.mgr.Systems()
	c.Assert(err, IsNil)
	c.Assert(systems, HasLen, 3)
	c.Check(systems, DeepEquals, []*devicestate.System{{
		Current:               false,
		DefaultRecoverySystem: true,
		Label:                 s.mockedSystemSeeds[0].label,
		Model:                 s.mockedSystemSeeds[0].model,
		Brand:                 s.mockedSystemSeeds[0].brand,
		Actions:               defaultSystemActions,
	}, {
		Current: false,
		Label:   s.mockedSystemSeeds[1].label,
		Model:   s.mockedSystemSeeds[1].model,
		Brand:   s.mockedSystemSeeds[1].brand,
		Actions: defaultSystemActions,
	}, {
		Current: false,
		Label:   s.mockedSystemSeeds[2].label,
		Model:   s.mockedSystemSeeds[2].model,
		Brand:   s.mockedSystemSeeds[2].brand,
		Actions: defaultSystemActions,
	}})
}

func (s *deviceMgrSystemsSuite) TestListSeedSystemsCurrentSingleSeeded(c *C) {
	s.state.Lock()
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[1].label,
			Model:   s.mockedSystemSeeds[1].model.Model(),
			BrandID: s.mockedSystemSeeds[1].brand.AccountID(),
		},
	})
	s.state.Unlock()

	systems, err := s.mgr.Systems()
	c.Assert(err, IsNil)
	c.Assert(systems, HasLen, 3)
	c.Check(systems, DeepEquals, []*devicestate.System{{
		Current: false,
		Label:   s.mockedSystemSeeds[0].label,
		Model:   s.mockedSystemSeeds[0].model,
		Brand:   s.mockedSystemSeeds[0].brand,
		Actions: defaultSystemActions,
	}, {
		// this seed was used for installing the running system
		Current: true,
		Label:   s.mockedSystemSeeds[1].label,
		Model:   s.mockedSystemSeeds[1].model,
		Brand:   s.mockedSystemSeeds[1].brand,
		Actions: currentSystemActions,
	}, {
		Current: false,
		Label:   s.mockedSystemSeeds[2].label,
		Model:   s.mockedSystemSeeds[2].model,
		Brand:   s.mockedSystemSeeds[2].brand,
		Actions: defaultSystemActions,
	}})
}

func (s *deviceMgrSystemsSuite) TestListSeedSystemsCurrentManySeeded(c *C) {
	// during a remodel, a new seeded system is prepended to the list
	s.state.Lock()
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[2].label,
			Model:   s.mockedSystemSeeds[2].model.Model(),
			BrandID: s.mockedSystemSeeds[2].brand.AccountID(),
		},
		{
			System:  s.mockedSystemSeeds[1].label,
			Model:   s.mockedSystemSeeds[1].model.Model(),
			BrandID: s.mockedSystemSeeds[1].brand.AccountID(),
		},
	})
	s.state.Unlock()

	systems, err := s.mgr.Systems()
	c.Assert(err, IsNil)
	c.Assert(systems, HasLen, 3)
	c.Check(systems, DeepEquals, []*devicestate.System{{
		Current: false,
		Label:   s.mockedSystemSeeds[0].label,
		Model:   s.mockedSystemSeeds[0].model,
		Brand:   s.mockedSystemSeeds[0].brand,
		Actions: defaultSystemActions,
	}, {
		// this seed was used to install the system in the past
		Current: false,
		Label:   s.mockedSystemSeeds[1].label,
		Model:   s.mockedSystemSeeds[1].model,
		Brand:   s.mockedSystemSeeds[1].brand,
		Actions: defaultSystemActions,
	}, {
		// this seed was seeded most recently
		Current: true,
		Label:   s.mockedSystemSeeds[2].label,
		Model:   s.mockedSystemSeeds[2].model,
		Brand:   s.mockedSystemSeeds[2].brand,
		Actions: currentSystemActions,
	}})
}

func (s *deviceMgrSystemsSuite) TestListSeedSystemsCurrentInRecoveryMode(c *C) {
	// mock recovery mode
	modeenv := boot.Modeenv{
		Mode:           "recover",
		RecoverySystem: s.mockedSystemSeeds[1].label,

		Model:          s.mockedSystemSeeds[1].model.Model(),
		BrandID:        s.mockedSystemSeeds[1].brand.AccountID(),
		Grade:          string(s.mockedSystemSeeds[1].model.Grade()),
		ModelSignKeyID: s.mockedSystemSeeds[1].model.SignKeyID(),
	}
	err := modeenv.WriteTo("")
	c.Assert(err, IsNil)
	// update the internal mode
	devicestate.SetSystemMode(s.mgr, "recover")

	s.state.Lock()
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[1].label,
			Model:   s.mockedSystemSeeds[1].model.Model(),
			BrandID: s.mockedSystemSeeds[1].brand.AccountID(),
		},
	})
	s.state.Unlock()

	systems, err := s.mgr.Systems()
	c.Assert(err, IsNil)
	c.Assert(systems, HasLen, 3)
	c.Check(systems, DeepEquals, []*devicestate.System{{
		Current: false,
		Label:   s.mockedSystemSeeds[0].label,
		Model:   s.mockedSystemSeeds[0].model,
		Brand:   s.mockedSystemSeeds[0].brand,
		Actions: defaultSystemActions,
	}, {
		// this seed was used for installing the running system, but
		// since we are in recovery mode, the available actions are
		// slightly different
		Current: true,
		Label:   s.mockedSystemSeeds[1].label,
		Model:   s.mockedSystemSeeds[1].model,
		Brand:   s.mockedSystemSeeds[1].brand,
		Actions: recoverySystemActions,
	}, {
		Current: false,
		Label:   s.mockedSystemSeeds[2].label,
		Model:   s.mockedSystemSeeds[2].model,
		Brand:   s.mockedSystemSeeds[2].brand,
		Actions: defaultSystemActions,
	}})
}

func (s *deviceMgrSystemsSuite) TestBrokenSeedSystems(c *C) {
	// break the first seed
	err := os.Remove(filepath.Join(dirs.SnapSeedDir, "systems", s.mockedSystemSeeds[0].label, "model"))
	c.Assert(err, IsNil)

	systems, err := s.mgr.Systems()
	c.Assert(err, IsNil)
	c.Assert(systems, HasLen, 2)
	c.Check(systems, DeepEquals, []*devicestate.System{{
		Current: false,
		Label:   s.mockedSystemSeeds[1].label,
		Model:   s.mockedSystemSeeds[1].model,
		Brand:   s.mockedSystemSeeds[1].brand,
		Actions: defaultSystemActions,
	}, {
		Current: false,
		Label:   s.mockedSystemSeeds[2].label,
		Model:   s.mockedSystemSeeds[2].model,
		Brand:   s.mockedSystemSeeds[2].brand,
		Actions: defaultSystemActions,
	}})
}

func (s *deviceMgrSystemsSuite) TestRequestModeInstallHappyForAny(c *C) {
	// no current system
	err := s.mgr.RequestSystemAction("20191119", devicestate.SystemAction{Mode: "install", Title: "Install"})
	c.Assert(err, IsNil)

	m, err := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"snapd_recovery_system": "20191119",
		"snapd_recovery_mode":   "install",
	})
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})
	c.Check(s.logbuf.String(), Matches, `.*: restarting into system "20191119" for action "Install"\n`)
}

func (s *deviceMgrSystemsSuite) TestRequestSameModeSameSystem(c *C) {
	s.state.Lock()
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[0].label,
			Model:   s.mockedSystemSeeds[0].model.Model(),
			BrandID: s.mockedSystemSeeds[0].brand.AccountID(),
		},
	})
	s.state.Unlock()

	label := s.mockedSystemSeeds[0].label

	happyModes := []string{"run"}
	sadModes := []string{"install", "recover", "factory-reset"}

	for _, mode := range append(happyModes, sadModes...) {
		s.logbuf.Reset()

		c.Logf("checking mode: %q", mode)
		// non run modes use modeenv
		modeenv := boot.Modeenv{
			Mode: mode,
		}
		if mode != "run" {
			modeenv.RecoverySystem = s.mockedSystemSeeds[0].label
		}
		err := modeenv.WriteTo("")
		c.Assert(err, IsNil)

		devicestate.SetSystemMode(s.mgr, mode)
		err = s.bootloader.SetBootVars(map[string]string{
			"snapd_recovery_mode":   mode,
			"snapd_recovery_system": label,
		})
		c.Assert(err, IsNil)
		err = s.mgr.RequestSystemAction(label, devicestate.SystemAction{Mode: mode})
		if strutil.ListContains(sadModes, mode) {
			c.Assert(err, Equals, devicestate.ErrUnsupportedAction)
		} else {
			c.Assert(err, IsNil)
		}
		// bootloader vars shouldn't change
		m, err := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
		c.Assert(err, IsNil)
		c.Check(m, DeepEquals, map[string]string{
			"snapd_recovery_mode":   mode,
			"snapd_recovery_system": label,
		})
		// should never restart
		c.Check(s.restartRequests, HasLen, 0)
		// no log output
		c.Check(s.logbuf.String(), Equals, "")
	}
}

func (s *deviceMgrSystemsSuite) TestRequestSeedingSameConflict(c *C) {
	label := s.mockedSystemSeeds[0].label

	devicestate.SetSystemMode(s.mgr, "run")

	s.state.Lock()
	s.state.Set("seeded", nil)
	s.state.Unlock()

	for _, mode := range []string{"run", "install", "recover", "factory-reset"} {
		s.logbuf.Reset()

		c.Logf("checking mode: %q", mode)
		modeenv := boot.Modeenv{
			Mode:           mode,
			RecoverySystem: s.mockedSystemSeeds[0].label,
		}
		err := modeenv.WriteTo("")
		c.Assert(err, IsNil)

		err = s.bootloader.SetBootVars(map[string]string{
			"snapd_recovery_mode":   "",
			"snapd_recovery_system": label,
		})
		c.Assert(err, IsNil)
		err = s.mgr.RequestSystemAction(label, devicestate.SystemAction{Mode: mode})
		c.Assert(err, ErrorMatches, "cannot request system action, system is seeding")
		// no log output
		c.Check(s.logbuf.String(), Equals, "")
	}
}

func (s *deviceMgrSystemsSuite) TestRequestSeedingDifferentNoConflict(c *C) {
	label := s.mockedSystemSeeds[0].label
	otherLabel := s.mockedSystemSeeds[1].label

	devicestate.SetSystemMode(s.mgr, "run")

	modeenv := boot.Modeenv{
		Mode:           "run",
		RecoverySystem: label,
	}
	err := modeenv.WriteTo("")
	c.Assert(err, IsNil)

	s.state.Lock()
	s.state.Set("seeded", nil)
	s.state.Unlock()

	// we can only go to install mode of other system when one is currently
	// being seeded
	err = s.bootloader.SetBootVars(map[string]string{
		"snapd_recovery_mode":   "",
		"snapd_recovery_system": label,
	})
	c.Assert(err, IsNil)
	err = s.mgr.RequestSystemAction(otherLabel, devicestate.SystemAction{Mode: "install"})
	c.Assert(err, IsNil)
	m, err := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"snapd_recovery_system": otherLabel,
		"snapd_recovery_mode":   "install",
	})
	c.Check(s.logbuf.String(), Matches, fmt.Sprintf(`.*: restarting into system "%s" for action "Install"\n`, otherLabel))
}

func (s *deviceMgrSystemsSuite) testRequestModeWithRestart(c *C, toModes []string, label string) {
	for _, mode := range toModes {
		c.Logf("checking mode: %q", mode)
		err := s.mgr.RequestSystemAction(label, devicestate.SystemAction{Mode: mode})
		c.Assert(err, IsNil)
		m, err := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
		c.Assert(err, IsNil)
		c.Check(m, DeepEquals, map[string]string{
			"snapd_recovery_system": label,
			"snapd_recovery_mode":   mode,
		})
		c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})
		s.restartRequests = nil
		s.bootloader.BootVars = map[string]string{}

		// TODO: also test correct action string logging
		c.Check(s.logbuf.String(), Matches, fmt.Sprintf(`.*: restarting into system "%s" for action ".*"\n`, label))
		s.logbuf.Reset()
	}
}

func (s *deviceMgrSystemsSuite) TestRequestModeRunInstallResetForRecover(c *C) {
	// we are in recover mode here
	devicestate.SetSystemMode(s.mgr, "recover")
	// non run modes use modeenv
	modeenv := boot.Modeenv{
		Mode:           "recover",
		RecoverySystem: s.mockedSystemSeeds[0].label,
	}
	err := modeenv.WriteTo("")
	c.Assert(err, IsNil)

	s.state.Lock()
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[0].label,
			Model:   s.mockedSystemSeeds[0].model.Model(),
			BrandID: s.mockedSystemSeeds[0].brand.AccountID(),
		},
	})
	s.state.Unlock()

	s.testRequestModeWithRestart(c, []string{"install", "run", "factory-reset"}, s.mockedSystemSeeds[0].label)
}

func (s *deviceMgrSystemsSuite) TestRequestModeInstallRecoverForCurrent(c *C) {
	devicestate.SetSystemMode(s.mgr, "run")
	// non run modes use modeenv
	modeenv := boot.Modeenv{
		Mode: "run",
	}
	err := modeenv.WriteTo("")
	c.Assert(err, IsNil)

	s.state.Lock()
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[0].label,
			Model:   s.mockedSystemSeeds[0].model.Model(),
			BrandID: s.mockedSystemSeeds[0].brand.AccountID(),
		},
	})
	s.state.Unlock()

	s.testRequestModeWithRestart(c, []string{"install", "recover", "factory-reset"}, s.mockedSystemSeeds[0].label)
}

func (s *deviceMgrSystemsSuite) TestRequestModeErrInBoot(c *C) {
	s.bootloader.SetErr = errors.New("no can do")
	err := s.mgr.RequestSystemAction("20191119", devicestate.SystemAction{Mode: "install"})
	c.Assert(err, ErrorMatches, `cannot set device to boot into system "20191119" in mode "install": no can do`)
	c.Check(s.restartRequests, HasLen, 0)
	c.Check(s.logbuf.String(), Equals, "")
}

func (s *deviceMgrSystemsSuite) TestRequestModeNotFound(c *C) {
	err := s.mgr.RequestSystemAction("not-found", devicestate.SystemAction{Mode: "install"})
	c.Assert(err, NotNil)
	c.Assert(os.IsNotExist(err), Equals, true)
	c.Check(s.restartRequests, HasLen, 0)
	c.Check(s.logbuf.String(), Equals, "")
}

func (s *deviceMgrSystemsSuite) TestRequestModeBadMode(c *C) {
	err := s.mgr.RequestSystemAction("20191119", devicestate.SystemAction{Mode: "unknown-mode"})
	c.Assert(err, Equals, devicestate.ErrUnsupportedAction)
	c.Check(s.restartRequests, HasLen, 0)
	c.Check(s.logbuf.String(), Equals, "")
}

func (s *deviceMgrSystemsSuite) TestRequestModeBroken(c *C) {
	// break the first seed
	err := os.Remove(filepath.Join(dirs.SnapSeedDir, "systems", s.mockedSystemSeeds[0].label, "model"))
	c.Assert(err, IsNil)

	err = s.mgr.RequestSystemAction("20191119", devicestate.SystemAction{Mode: "install"})
	c.Assert(err, ErrorMatches, `cannot load seed system: cannot load assertions for label "20191119": .*`)
	c.Check(s.restartRequests, HasLen, 0)
	c.Check(s.logbuf.String(), Equals, "")
}

func (s *deviceMgrSystemsSuite) TestRequestModeNonUC20(c *C) {
	s.setPCModelInState(c)
	err := s.mgr.RequestSystemAction("20191119", devicestate.SystemAction{Mode: "install"})
	c.Assert(err, ErrorMatches, `cannot set device to boot into system "20191119" in mode "install": system mode is unsupported`)
	c.Check(s.restartRequests, HasLen, 0)
	c.Check(s.logbuf.String(), Equals, "")
}

func (s *deviceMgrSystemsSuite) TestRequestActionNoLabel(c *C) {
	err := s.mgr.RequestSystemAction("", devicestate.SystemAction{Mode: "install"})
	c.Assert(err, ErrorMatches, "internal error: system label is unset")
	c.Check(s.logbuf.String(), Equals, "")
}

func (s *deviceMgrSystemsSuite) TestRequestModeForNonCurrent(c *C) {
	s.state.Lock()
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[0].label,
			Model:   s.mockedSystemSeeds[0].model.Model(),
			BrandID: s.mockedSystemSeeds[0].brand.AccountID(),
		},
	})

	s.state.Unlock()
	s.setPCModelInState(c)
	// request mode reserved for current system
	err := s.mgr.RequestSystemAction(s.mockedSystemSeeds[1].label, devicestate.SystemAction{Mode: "run"})
	c.Assert(err, Equals, devicestate.ErrUnsupportedAction)
	c.Check(s.restartRequests, HasLen, 0)
	c.Check(s.logbuf.String(), Equals, "")
}

func (s *deviceMgrSystemsSuite) TestRequestInstallForOther(c *C) {
	devicestate.SetSystemMode(s.mgr, "run")
	// non run modes use modeenv
	modeenv := boot.Modeenv{
		Mode: "run",
	}
	err := modeenv.WriteTo("")
	c.Assert(err, IsNil)

	s.state.Lock()
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[0].label,
			Model:   s.mockedSystemSeeds[0].model.Model(),
			BrandID: s.mockedSystemSeeds[0].brand.AccountID(),
		},
	})
	s.state.Unlock()
	// reinstall from different system seed is ok
	s.testRequestModeWithRestart(c, []string{"install"}, s.mockedSystemSeeds[1].label)
}

func (s *deviceMgrSystemsSuite) TestRequestAction1618(c *C) {
	s.setPCModelInState(c)
	// system mode is unset in 16/18
	devicestate.SetSystemMode(s.mgr, "")
	// no modeenv either
	err := os.Remove(dirs.SnapModeenvFileUnder(dirs.GlobalRootDir))
	c.Assert(err, IsNil)

	s.state.Lock()
	s.state.Set("seeded-systems", nil)
	s.state.Set("seeded", nil)
	s.state.Unlock()
	// a label exists
	err = s.mgr.RequestSystemAction(s.mockedSystemSeeds[0].label, devicestate.SystemAction{Mode: "install"})
	c.Assert(err, ErrorMatches, "cannot set device to boot .*: system mode is unsupported")

	s.state.Lock()
	s.state.Set("seeded", true)
	s.state.Unlock()

	// even with system mode explicitly set, the action is not executed
	devicestate.SetSystemMode(s.mgr, "run")

	err = s.mgr.RequestSystemAction(s.mockedSystemSeeds[0].label, devicestate.SystemAction{Mode: "install"})
	c.Assert(err, ErrorMatches, "cannot set device to boot .*: system mode is unsupported")

	devicestate.SetSystemMode(s.mgr, "")
	// also no UC20 style system seeds
	for _, m := range s.mockedSystemSeeds {
		os.RemoveAll(filepath.Join(dirs.SnapSeedDir, "systems", m.label))
	}

	err = s.mgr.RequestSystemAction(s.mockedSystemSeeds[0].label, devicestate.SystemAction{Mode: "install"})
	c.Assert(err, ErrorMatches, ".*/seed/systems/20191119: no such file or directory")
	c.Check(s.logbuf.String(), Equals, "")
}

func (s *deviceMgrSystemsSuite) TestRebootNoLabelNoModeHappy(c *C) {
	err := s.mgr.Reboot("", "")
	c.Assert(err, IsNil)

	m, err := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
	c.Assert(err, IsNil)
	// requested restart
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})
	// but no bootloader changes
	c.Check(m, DeepEquals, map[string]string{
		"snapd_recovery_system": "",
		"snapd_recovery_mode":   "",
	})
	c.Check(s.logbuf.String(), Matches, `.*: rebooting system\n`)
}

func (s *deviceMgrSystemsSuite) TestRebootLabelAndModeHappy(c *C) {
	s.state.Lock()
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[0].label,
			Model:   s.mockedSystemSeeds[0].model.Model(),
			BrandID: s.mockedSystemSeeds[0].brand.AccountID(),
		},
	})
	s.state.Unlock()

	err := s.mgr.Reboot("20191119", "install")
	c.Assert(err, IsNil)

	m, err := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"snapd_recovery_system": "20191119",
		"snapd_recovery_mode":   "install",
	})
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})
	c.Check(s.logbuf.String(), Matches, `.*: rebooting into system "20191119" in "install" mode\n`)
}

func (s *deviceMgrSystemsSuite) TestRebootFromRunOnlyHappy(c *C) {
	const setDefault = true
	s.testRebootFromRunOnly(c, setDefault)
}

func (s *deviceMgrSystemsSuite) TestRebootFromRunOnlyFallBackToCurrent(c *C) {
	const setDefault = false
	s.testRebootFromRunOnly(c, setDefault)
}

func (s *deviceMgrSystemsSuite) testRebootFromRunOnly(c *C, setDefault bool) {
	s.state.Lock()
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[0].label,
			Model:   s.mockedSystemSeeds[0].model.Model(),
			BrandID: s.mockedSystemSeeds[0].brand.AccountID(),
		},
	})

	var expectedLabel string
	if setDefault {
		expectedLabel = "20200318"
		s.state.Set("default-recovery-system", devicestate.DefaultRecoverySystem{
			System:   expectedLabel,
			Model:    "model",
			BrandID:  "brand",
			Revision: 1,
		})
	} else {
		expectedLabel = s.mockedSystemSeeds[0].label
	}

	s.state.Unlock()

	for _, mode := range []string{"recover", "install", "factory-reset"} {
		s.restartRequests = nil
		s.bootloader.BootVars = make(map[string]string)
		s.logbuf.Reset()

		err := s.mgr.Reboot("", mode)
		c.Assert(err, IsNil)

		m, err := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
		c.Assert(err, IsNil)
		c.Check(m, DeepEquals, map[string]string{
			"snapd_recovery_system": expectedLabel,
			"snapd_recovery_mode":   mode,
		})
		c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})
		c.Check(s.logbuf.String(), Matches, fmt.Sprintf(`.*: rebooting into system "%s" in "%s" mode\n`, expectedLabel, mode))
	}
}

func (s *deviceMgrSystemsSuite) TestRebootFromRecoverToOther(c *C) {
	modeenv := boot.Modeenv{
		Mode:           "recover",
		RecoverySystem: s.mockedSystemSeeds[0].label,
	}
	err := modeenv.WriteTo("")
	c.Assert(err, IsNil)

	devicestate.SetSystemMode(s.mgr, "recover")
	err = s.bootloader.SetBootVars(map[string]string{
		"snapd_recovery_mode":   "recover",
		"snapd_recovery_system": s.mockedSystemSeeds[0].label,
	})
	c.Assert(err, IsNil)

	s.state.Lock()
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[0].label,
			Model:   s.mockedSystemSeeds[0].model.Model(),
			BrandID: s.mockedSystemSeeds[0].brand.AccountID(),
		},
	})
	s.state.Unlock()

	for _, mode := range []string{"run", "factory-reset"} {
		s.restartRequests = nil
		s.bootloader.BootVars = make(map[string]string)
		s.logbuf.Reset()

		err = s.mgr.Reboot("", mode)
		c.Assert(err, IsNil)

		m, err := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
		c.Assert(err, IsNil)
		c.Check(m, DeepEquals, map[string]string{
			"snapd_recovery_mode":   mode,
			"snapd_recovery_system": s.mockedSystemSeeds[0].label,
		})
		c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})
		c.Check(s.logbuf.String(), Matches, fmt.Sprintf(`.*: rebooting into system "%s" in "%s" mode\n`, s.mockedSystemSeeds[0].label, mode))
	}
}

func (s *deviceMgrSystemsSuite) TestRebootAlreadyInRunMode(c *C) {
	devicestate.SetSystemMode(s.mgr, "run")

	s.state.Lock()
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[0].label,
			Model:   s.mockedSystemSeeds[0].model.Model(),
			BrandID: s.mockedSystemSeeds[0].brand.AccountID(),
		},
	})
	s.state.Unlock()

	// we are already in "run" mode so this should just reboot
	err := s.mgr.Reboot("", "run")
	c.Assert(err, IsNil)

	m, err := s.bootloader.GetBootVars("snapd_recovery_mode", "snapd_recovery_system")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"snapd_recovery_mode":   "",
		"snapd_recovery_system": "",
	})
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})
	c.Check(s.logbuf.String(), Matches, `.*: rebooting system\n`)
}

func (s *deviceMgrSystemsSuite) TestRebootUnhappy(c *C) {
	s.state.Lock()
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  s.mockedSystemSeeds[0].label,
			Model:   s.mockedSystemSeeds[0].model.Model(),
			BrandID: s.mockedSystemSeeds[0].brand.AccountID(),
		},
	})
	s.state.Unlock()

	errUnsupportedActionStr := devicestate.ErrUnsupportedAction.Error()
	for _, tc := range []struct {
		systemLabel, mode string
		expectedErr       string
	}{
		{"", "unknown-mode", errUnsupportedActionStr},
		{"unknown-system", "run", `stat /.*: no such file or directory`},
		{"unknown-system", "unknown-mode", `stat /.*: no such file or directory`},
	} {
		s.restartRequests = nil
		s.bootloader.BootVars = make(map[string]string)

		err := s.mgr.Reboot(tc.systemLabel, tc.mode)
		c.Assert(err, ErrorMatches, tc.expectedErr)

		c.Check(s.restartRequests, HasLen, 0)
		c.Check(s.logbuf.String(), Equals, "")
	}
	c.Check(s.logbuf.String(), Equals, "")
}

func (s *deviceMgrSystemsSuite) TestDeviceManagerEnsureTriedSystemSuccessfuly(c *C) {
	err := s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "1234",
		"recovery_system_status": "tried",
	})
	c.Assert(err, IsNil)
	devicestate.SetBootOkRan(s.mgr, true)

	modeenv := boot.Modeenv{
		Mode: boot.ModeRun,
		// the system is in CurrentRecoverySystems
		CurrentRecoverySystems: []string{"29112019", "1234"},
	}
	err = modeenv.WriteTo("")
	c.Assert(err, IsNil)

	// system is considered successful, bootenv is cleared, the label is
	// recorded in tried-systems
	err = s.mgr.Ensure()
	c.Assert(err, IsNil)

	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})

	var triedSystems []string
	s.state.Lock()
	err = s.state.Get("tried-systems", &triedSystems)
	c.Assert(err, IsNil)
	c.Check(triedSystems, DeepEquals, []string{"1234"})
	// also logged
	c.Check(s.logbuf.String(), testutil.Contains, `tried recovery system "1234" was successful`)
	s.state.Unlock()

	// reset and run again, we need to populate boot variables again
	err = s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "1234",
		"recovery_system_status": "tried",
	})
	c.Assert(err, IsNil)
	devicestate.SetTriedSystemsRan(s.mgr, false)

	err = s.mgr.Ensure()
	c.Assert(err, IsNil)
	s.state.Lock()
	defer s.state.Unlock()
	err = s.state.Get("tried-systems", &triedSystems)
	c.Assert(err, IsNil)
	// the system was already there, no duplicate got appended
	c.Assert(triedSystems, DeepEquals, []string{"1234"})
}

func (s *deviceMgrSystemsSuite) TestDeviceManagerEnsureTriedSystemMissingInModeenvUnhappy(c *C) {
	err := s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "1234",
		"recovery_system_status": "tried",
	})
	c.Assert(err, IsNil)
	devicestate.SetBootOkRan(s.mgr, true)

	modeenv := boot.Modeenv{
		Mode: boot.ModeRun,
		// the system is not in CurrentRecoverySystems
		CurrentRecoverySystems: []string{"29112019"},
	}
	err = modeenv.WriteTo("")
	c.Assert(err, IsNil)

	// system is considered successful, bootenv is cleared, the label is
	// recorded in tried-systems
	err = s.mgr.Ensure()
	c.Assert(err, IsNil)

	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})

	var triedSystems []string
	s.state.Lock()
	err = s.state.Get("tried-systems", &triedSystems)
	c.Assert(err, testutil.ErrorIs, state.ErrNoState)
	// also logged
	c.Check(s.logbuf.String(), testutil.Contains, `tried recovery system outcome error: recovery system "1234" was tried, but is not present in the modeenv CurrentRecoverySystems`)
	s.state.Unlock()
}

func (s *deviceMgrSystemsSuite) TestDeviceManagerEnsureTriedSystemBad(c *C) {
	// after reboot, the recovery system status is still try
	err := s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "1234",
		"recovery_system_status": "try",
	})
	c.Assert(err, IsNil)
	devicestate.SetBootOkRan(s.mgr, true)

	// thus the system is considered bad, bootenv is cleared, and system is
	// not recorded as successful
	err = s.mgr.Ensure()
	c.Assert(err, IsNil)

	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})

	var triedSystems []string
	s.state.Lock()
	err = s.state.Get("tried-systems", &triedSystems)
	c.Assert(err, testutil.ErrorIs, state.ErrNoState)
	c.Check(s.logbuf.String(), testutil.Contains, `tried recovery system "1234" failed`)
	s.state.Unlock()

	// procure an inconsistent state, reset and run again
	err = s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "try",
	})
	c.Assert(err, IsNil)
	devicestate.SetTriedSystemsRan(s.mgr, false)

	// clear the log buffer
	s.logbuf.Reset()

	err = s.mgr.Ensure()
	c.Assert(err, IsNil)
	s.state.Lock()
	defer s.state.Unlock()
	err = s.state.Get("tried-systems", &triedSystems)
	c.Assert(err, testutil.ErrorIs, state.ErrNoState)
	// bootenv got cleared
	m, err = s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	c.Check(s.logbuf.String(), testutil.Contains, `tried recovery system outcome error: try recovery system is unset but status is "try"`)
	c.Check(s.logbuf.String(), testutil.Contains, `inconsistent outcome of a tried recovery system`)
}

func (s *deviceMgrSystemsSuite) TestDeviceManagerEnsureTriedSystemManyLabels(c *C) {
	err := s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "1234",
		"recovery_system_status": "tried",
	})
	c.Assert(err, IsNil)
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	s.state.Set("tried-systems", []string{"0000", "1111"})
	s.state.Unlock()

	modeenv := boot.Modeenv{
		Mode: boot.ModeRun,
		// the system is in CurrentRecoverySystems
		CurrentRecoverySystems: []string{"29112019", "1234"},
	}
	err = modeenv.WriteTo("")
	c.Assert(err, IsNil)

	// successful system label is appended
	err = s.mgr.Ensure()
	c.Assert(err, IsNil)

	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})

	s.state.Lock()
	defer s.state.Unlock()

	var triedSystems []string
	err = s.state.Get("tried-systems", &triedSystems)
	c.Assert(err, IsNil)
	c.Assert(triedSystems, DeepEquals, []string{"0000", "1111", "1234"})

	c.Check(s.logbuf.String(), testutil.Contains, `tried recovery system "1234" was successful`)
}

func (s *deviceMgrSystemsSuite) TestRecordSeededSystem(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	now := time.Now()
	modelTs := now.AddDate(-1, 0, 0)

	sys := devicestate.SeededSystem{
		System: "1234",

		Model:     "my-model",
		BrandID:   "my-brand",
		Revision:  1,
		Timestamp: modelTs,

		SeedTime: now,
	}
	err := devicestate.RecordSeededSystem(s.mgr, s.state, &sys)
	c.Assert(err, IsNil)

	expectedSeededOneSys := []map[string]any{
		{
			"system":    "1234",
			"model":     "my-model",
			"brand-id":  "my-brand",
			"revision":  float64(1),
			"timestamp": modelTs.Format(time.RFC3339Nano),
			"seed-time": now.Format(time.RFC3339Nano),
		},
	}
	var seededSystemsFromState []map[string]any
	err = s.state.Get("seeded-systems", &seededSystemsFromState)
	c.Assert(err, IsNil)
	c.Assert(seededSystemsFromState, DeepEquals, expectedSeededOneSys)
	// adding the system again does nothing
	err = devicestate.RecordSeededSystem(s.mgr, s.state, &sys)
	c.Assert(err, IsNil)
	err = s.state.Get("seeded-systems", &seededSystemsFromState)
	c.Assert(err, IsNil)
	c.Assert(seededSystemsFromState, DeepEquals, expectedSeededOneSys)
	// adding the system again, even with changed seed time, still does nothing
	sysWithNewSeedTime := sys
	sysWithNewSeedTime.SeedTime = now.Add(time.Hour)
	err = devicestate.RecordSeededSystem(s.mgr, s.state, &sysWithNewSeedTime)
	c.Assert(err, IsNil)
	err = s.state.Get("seeded-systems", &seededSystemsFromState)
	c.Assert(err, IsNil)
	c.Assert(seededSystemsFromState, DeepEquals, expectedSeededOneSys)

	rev3Ts := modelTs.AddDate(0, 1, 0)
	// most common case, a new revision and timestamp
	sysRev3 := sys
	sysRev3.Revision = 3
	sysRev3.Timestamp = rev3Ts

	err = devicestate.RecordSeededSystem(s.mgr, s.state, &sysRev3)
	c.Assert(err, IsNil)
	err = s.state.Get("seeded-systems", &seededSystemsFromState)
	c.Assert(err, IsNil)
	expectedWithNewRev := []map[string]any{
		{
			// new entry is added at the beginning
			"system":    "1234",
			"model":     "my-model",
			"brand-id":  "my-brand",
			"revision":  float64(3),
			"timestamp": rev3Ts.Format(time.RFC3339Nano),
			"seed-time": now.Format(time.RFC3339Nano),
		}, {
			"system":    "1234",
			"model":     "my-model",
			"brand-id":  "my-brand",
			"revision":  float64(1),
			"timestamp": modelTs.Format(time.RFC3339Nano),
			"seed-time": now.Format(time.RFC3339Nano),
		},
	}
	c.Assert(seededSystemsFromState, DeepEquals, expectedWithNewRev)
	// trying to add again does nothing
	err = devicestate.RecordSeededSystem(s.mgr, s.state, &sysRev3)
	c.Assert(err, IsNil)
	err = s.state.Get("seeded-systems", &seededSystemsFromState)
	c.Assert(err, IsNil)
	c.Assert(seededSystemsFromState, DeepEquals, expectedWithNewRev)

	modelNewTs := modelTs
	// and a case of new model
	sysNew := devicestate.SeededSystem{
		System: "9999",

		Model:     "my-new-model",
		BrandID:   "my-new-brand",
		Revision:  1,
		Timestamp: modelNewTs,

		SeedTime: now,
	}
	err = devicestate.RecordSeededSystem(s.mgr, s.state, &sysNew)
	c.Assert(err, IsNil)
	err = s.state.Get("seeded-systems", &seededSystemsFromState)
	c.Assert(err, IsNil)
	expectedWithNewModel := []map[string]any{
		{
			// and another one got added at the beginning
			"system":    "9999",
			"model":     "my-new-model",
			"brand-id":  "my-new-brand",
			"revision":  float64(1),
			"timestamp": modelNewTs.Format(time.RFC3339Nano),
			"seed-time": now.Format(time.RFC3339Nano),
		}, {
			"system":    "1234",
			"model":     "my-model",
			"brand-id":  "my-brand",
			"revision":  float64(3),
			"timestamp": rev3Ts.Format(time.RFC3339Nano),
			"seed-time": now.Format(time.RFC3339Nano),
		}, {
			"system":    "1234",
			"model":     "my-model",
			"brand-id":  "my-brand",
			"revision":  float64(1),
			"timestamp": modelTs.Format(time.RFC3339Nano),
			"seed-time": now.Format(time.RFC3339Nano),
		},
	}
	c.Assert(seededSystemsFromState, DeepEquals, expectedWithNewModel)
}

type deviceMgrSystemsCreateSuite struct {
	deviceMgrSystemsBaseSuite

	bootloader *bootloadertest.MockRecoveryAwareTrustedAssetsBootloader
}

func (s *deviceMgrSystemsCreateSuite) SetUpTest(c *C) {
	s.deviceMgrSystemsBaseSuite.SetUpTest(c)

	s.state.Lock()
	defer s.state.Unlock()
	s.makeSnapInState(c, "pc", snap.R(1), nil, nil)
	s.makeSnapInState(c, "pc-kernel", snap.R(2), nil, nil)
	s.makeSnapInState(c, "core20", snap.R(3), nil, nil)
	s.makeSnapInState(c, "snapd", snap.R(4), nil, nil)

	s.bootloader = s.deviceMgrSystemsBaseSuite.bootloader.WithRecoveryAwareTrustedAssets()
	bootloader.Force(s.bootloader)
	s.AddCleanup(func() { bootloader.Force(nil) })
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemConflict(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	devicestate.SetBootOkRan(s.mgr, true)

	for _, chgType := range []string{"create-recovery-system", "remove-recovery-system", "remodel"} {
		conflict := s.state.NewChange(chgType, "...")
		conflict.AddTask(s.state.NewTask(chgType, "..."))

		_, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{})
		conflictErr, ok := err.(*snapstate.ChangeConflictError)
		c.Assert(ok, Equals, true, Commentf("expected a snapstate.ChangeConflictError, got %T", err))

		c.Check(conflictErr.ChangeID, Equals, conflict.ID())
		c.Check(conflictErr.ChangeKind, Equals, conflict.Kind())

		conflict.Abort()
		s.waitfor(conflict)

		conflict.Abort()
		s.waitfor(conflict)
	}
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemTasksAndChange(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()
	chg, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		TestSystem: true,
	})
	c.Assert(err, IsNil)
	c.Assert(chg, NotNil)
	tsks := chg.Tasks()
	c.Check(tsks, HasLen, 2)
	tskCreate := tsks[0]
	tskFinalize := tsks[1]
	c.Check(tskCreate.Summary(), Matches, `Create recovery system with label "1234"`)
	c.Check(tskFinalize.Summary(), Matches, `Finalize recovery system with label "1234"`)
	var systemSetupData map[string]any
	err = tskCreate.Get("recovery-system-setup", &systemSetupData)
	c.Assert(err, IsNil)
	c.Assert(systemSetupData, DeepEquals, map[string]any{
		"label":       "1234",
		"directory":   filepath.Join(boot.InitramfsUbuntuSeedDir, "systems/1234"),
		"test-system": true,
	})

	var otherTaskID string
	err = tskFinalize.Get("recovery-system-setup-task", &otherTaskID)
	c.Assert(err, IsNil)
	c.Assert(otherTaskID, Equals, tskCreate.ID())
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemTasksWhenDirExists(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	c.Assert(os.MkdirAll(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems/1234"), 0755), IsNil)

	s.state.Lock()
	defer s.state.Unlock()
	chg, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{})
	c.Assert(err, ErrorMatches, `recovery system "1234" already exists`)
	c.Check(chg, IsNil)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemNotSeeded(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()
	s.state.Set("seeded", nil)

	chg, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{})
	c.Assert(err, ErrorMatches, `cannot create new recovery systems until fully seeded`)
	c.Check(chg, IsNil)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoveryRequiredInVsetNotInModel(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	s.model = s.brands.Model("canonical", "pc-20", map[string]any{
		"architecture": "amd64",
		"grade":        "dangerous",
		"base":         "core20",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel",
				"id":              s.ss.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]any{
				"name":            "pc",
				"id":              s.ss.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
		},
		"revision": "2",
	})

	vset, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "required-snap",
				"id":       s.ss.AssertedSnapID("other"),
				"presence": "required",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	chg, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		ValidationSets: []*asserts.ValidationSet{vset.(*asserts.ValidationSet)},
	})
	c.Assert(err, ErrorMatches, `missing required snap in model: required-snap`)
	c.Check(chg, IsNil)
}

func (s *deviceMgrSystemsCreateSuite) makeSnapInState(c *C, name string, rev snap.Revision, extraFiles [][]string, components map[string]snap.Revision) *snap.Info {
	snapID := s.ss.AssertedSnapID(name)
	if rev.Unset() || rev.Local() {
		snapID = ""
	}
	si := &snap.SideInfo{
		RealName: name,
		SnapID:   snapID,
		Revision: rev,
	}

	files := append(extraFiles, snapFiles[name]...)

	info := snaptest.MakeSnapFileAndDir(c, snapYamls[name], files, si)
	// asserted?
	if !rev.Unset() && !rev.Local() {
		s.setupSnapDecl(c, info, "canonical")
		s.setupSnapRevision(c, info, "canonical", rev)
	}

	seq := snapstatetest.NewSequenceFromSnapSideInfos([]*snap.SideInfo{si})

	for comp, compRev := range components {
		if rev.Unset() {
			continue
		}

		cref := naming.NewComponentRef(name, comp)

		compYaml, ok := componentYamls[cref.String()]
		c.Assert(ok, Equals, true, Commentf("component.yaml not found for %q", name))

		compPath := snaptest.MakeTestComponent(c, compYaml)

		csi := snap.ComponentSideInfo{
			Component: cref,
			Revision:  compRev,
		}

		compInfo := snaptest.MockComponent(c, compYaml, info, csi)

		cpi := snap.MinimalComponentContainerPlaceInfo(
			comp,
			compRev,
			name,
		)
		err := os.Rename(compPath, cpi.MountFile())
		c.Assert(err, IsNil)

		s.setupSnapResourcePair(
			c,
			comp,
			snapID,
			"canonical",
			compRev,
			rev,
		)

		s.setupSnapResourceRevision(
			c,
			cpi.MountFile(),
			comp,
			snapID,
			"canonical",
			compRev,
		)

		err = seq.AddComponentForRevision(rev, sequence.NewComponentState(snap.NewComponentSideInfo(cref, compRev), compInfo.Type))
		c.Assert(err, IsNil)
	}

	snapstate.Set(s.state, info.InstanceName(), &snapstate.SnapState{
		SnapType: string(info.Type()),
		Active:   true,
		Sequence: seq,
		Current:  si.Revision,
	})

	return info
}

func (s *deviceMgrSystemsCreateSuite) mockStandardSnapsModeenvAndBootloaderState(c *C) {
	s.makeSnapInState(c, "pc", snap.R(1), nil, nil)
	s.makeSnapInState(c, "pc-kernel", snap.R(2), nil, nil)
	s.makeSnapInState(c, "core20", snap.R(3), nil, nil)
	s.makeSnapInState(c, "snapd", snap.R(4), nil, nil)

	err := s.bootloader.SetBootVars(map[string]string{
		"snap_kernel": "pc-kernel_2.snap",
		"snap_core":   "core20_3.snap",
	})
	c.Assert(err, IsNil)
	modeenv := boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	}
	err = modeenv.WriteTo("")
	c.Assert(err, IsNil)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemHappy(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	chg, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		TestSystem: true,
	})
	c.Assert(err, IsNil)
	c.Assert(chg, NotNil)
	tsks := chg.Tasks()
	c.Check(tsks, HasLen, 2)
	tskCreate := tsks[0]
	tskFinalize := tsks[1]
	c.Assert(tskCreate.Summary(), Matches, `Create recovery system with label "1234"`)
	c.Check(tskFinalize.Summary(), Matches, `Finalize recovery system with label "1234"`)

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), IsNil)
	c.Assert(tskCreate.Status(), Equals, state.WaitStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoStatus)
	// a reboot is expected
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})

	validateCore20Seed(c, "1234", s.model, s.storeSigning.Trusted)
	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "1234",
		"recovery_system_status": "try",
	})
	modeenvAfterCreate, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterCreate, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
		// try model is unset as its measured properties are identical
		// to current
	})
	// verify that new files are tracked correctly
	expectedFilesLog := &bytes.Buffer{}
	// new snap files are logged in this order
	for _, fname := range []string{"snapd_4.snap", "pc-kernel_2.snap", "core20_3.snap", "pc_1.snap"} {
		fmt.Fprintln(expectedFilesLog, filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps", fname))
	}
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"),
		testutil.FileEquals, expectedFilesLog.String())

	// these things happen on snapd startup
	restart.MockPending(s.state, restart.RestartUnset)
	s.state.Set("tried-systems", []string{"1234"})
	s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	s.bootloader.SetBootVarsCalls = 0

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()
	defer s.state.Unlock()

	// simulate a restart and run change to completion
	s.mockRestartAndSettle(c, s.state, chg)

	c.Assert(chg.Err(), IsNil)
	c.Check(chg.IsReady(), Equals, true)
	c.Assert(tskCreate.Status(), Equals, state.DoneStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoneStatus)

	var triedSystemsAfterFinalize []string
	err = s.state.Get("tried-systems", &triedSystemsAfterFinalize)
	c.Assert(err, testutil.ErrorIs, state.ErrNoState)

	modeenvAfterFinalize, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterFinalize, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem", "1234"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})
	// expect 1 more call to bootloader.SetBootVars, since we're marking this
	// system as seeded
	c.Check(s.bootloader.SetBootVarsCalls, Equals, 1)
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"), testutil.FileAbsent)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemRemodelDownloadingSnapsHappy(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	fooSnap := snaptest.MakeTestSnapWithFiles(c, "name: foo\nversion: 1.0\nbase: core20", nil)
	barSnap := snaptest.MakeTestSnapWithFiles(c, "name: bar\nversion: 1.0\nbase: core20", nil)
	s.state.Lock()
	// fake downloads are a nop
	tSnapsup1 := s.state.NewTask("fake-download", "test task carrying snap setup")
	tSnapsup2 := s.state.NewTask("fake-download", "test task carrying snap setup")
	// both snaps are asserted
	snapsupFoo := snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{RealName: "foo", SnapID: s.ss.AssertedSnapID("foo"), Revision: snap.R(99)},
		SnapPath: fooSnap,
	}
	s.setupSnapDeclForNameAndID(c, "foo", s.ss.AssertedSnapID("foo"), "canonical")
	s.setupSnapRevisionForFileAndID(c, fooSnap, s.ss.AssertedSnapID("foo"), "canonical", snap.R(99))
	snapsupBar := snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{RealName: "bar", SnapID: s.ss.AssertedSnapID("bar"), Revision: snap.R(100)},
		SnapPath: barSnap,
	}
	s.setupSnapDeclForNameAndID(c, "bar", s.ss.AssertedSnapID("bar"), "canonical")
	s.setupSnapRevisionForFileAndID(c, barSnap, s.ss.AssertedSnapID("bar"), "canonical", snap.R(100))
	// when download completes, the files will be at /var/lib/snapd/snap
	c.Assert(os.MkdirAll(filepath.Dir(snapsupFoo.BlobPath()), 0755), IsNil)
	c.Assert(os.Rename(fooSnap, snapsupFoo.BlobPath()), IsNil)
	c.Assert(os.MkdirAll(filepath.Dir(snapsupBar.BlobPath()), 0755), IsNil)
	c.Assert(os.Rename(barSnap, snapsupBar.BlobPath()), IsNil)
	tSnapsup1.Set("snap-setup", snapsupFoo)
	tSnapsup2.Set("snap-setup", snapsupBar)

	tss, err := devicestate.CreateRecoverySystemTasks(s.state, "1234", []string{tSnapsup1.ID(), tSnapsup2.ID()}, nil, devicestate.CreateRecoverySystemOptions{
		TestSystem: true,
	})
	c.Assert(err, IsNil)
	tsks := tss.Tasks()
	c.Check(tsks, HasLen, 2)
	tskCreate := tsks[0]
	tskFinalize := tsks[1]
	c.Assert(tskCreate.Summary(), Matches, `Create recovery system with label "1234"`)
	c.Check(tskFinalize.Summary(), Matches, `Finalize recovery system with label "1234"`)
	var systemSetupData map[string]any
	err = tskCreate.Get("recovery-system-setup", &systemSetupData)
	c.Assert(err, IsNil)
	c.Assert(systemSetupData, DeepEquals, map[string]any{
		"label":            "1234",
		"directory":        filepath.Join(boot.InitramfsUbuntuSeedDir, "systems/1234"),
		"snap-setup-tasks": []any{tSnapsup1.ID(), tSnapsup2.ID()},
		"test-system":      true,
	})
	tss.WaitFor(tSnapsup1)
	tss.WaitFor(tSnapsup2)
	// add the test tasks to the change
	chg := s.state.NewChange("create-recovery-system", "create recovery system")
	chg.AddTask(tSnapsup1)
	chg.AddTask(tSnapsup2)
	chg.AddAll(tss)

	// downloads are only accepted if the tasks are executed as part of
	// remodel, so procure a new model
	newModel := s.brands.Model("canonical", "pc-20", map[string]any{
		"architecture": "amd64",
		// UC20
		"grade": "dangerous",
		"base":  "core20",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel",
				"id":              s.ss.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]any{
				"name":            "pc",
				"id":              s.ss.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
			map[string]any{
				"name":     "foo",
				"id":       s.ss.AssertedSnapID("foo"),
				"presence": "required",
			},
			map[string]any{
				"name":     "bar",
				"presence": "required",
			},
		},
		"revision": "2",
	})
	chg.Set("new-model", string(asserts.Encode(newModel)))

	s.mockStandardSnapsModeenvAndBootloaderState(c)

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()
	defer s.state.Unlock()

	c.Assert(chg.Err(), IsNil)
	c.Assert(tskCreate.Status(), Equals, state.WaitStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoStatus)
	// a reboot is expected
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})

	validateCore20Seed(c, "1234", newModel, s.storeSigning.Trusted, "foo", "bar")
	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "1234",
		"recovery_system_status": "try",
	})
	modeenvAfterCreate, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterCreate, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
		// try model is unset as its measured properties are identical
	})
	// verify that new files are tracked correctly
	expectedFilesLog := &bytes.Buffer{}
	// new snap files are logged in this order
	for _, fname := range []string{
		"snapd_4.snap", "pc-kernel_2.snap", "core20_3.snap", "pc_1.snap",
		"foo_99.snap", "bar_100.snap",
	} {
		fmt.Fprintln(expectedFilesLog, filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps", fname))
	}
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"),
		testutil.FileEquals, expectedFilesLog.String())

	// these things happen on snapd startup
	restart.MockPending(s.state, restart.RestartUnset)
	s.state.Set("tried-systems", []string{"1234"})
	s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	s.bootloader.SetBootVarsCalls = 0

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	// simulate a restart and run change to completion
	s.mockRestartAndSettle(c, s.state, chg)

	c.Assert(chg.Err(), IsNil)
	c.Check(chg.IsReady(), Equals, true)
	c.Assert(tskCreate.Status(), Equals, state.DoneStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoneStatus)

	// this would be part of a remodel so some state is cleaned up only at the end of remodel change
	var triedSystemsAfterFinalize []string
	err = s.state.Get("tried-systems", &triedSystemsAfterFinalize)
	c.Assert(err, IsNil)
	c.Check(triedSystemsAfterFinalize, DeepEquals, []string{"1234"})

	modeenvAfterFinalize, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterFinalize, testutil.JsonEquals, boot.Modeenv{
		Mode:           "run",
		Base:           "core20_3.snap",
		CurrentKernels: []string{"pc-kernel_2.snap"},
		// the system is kept in the current list
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		// but not promoted to good systems yet
		GoodRecoverySystems: []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})
	// since this is part of a remodel, we don't expect any more calls to
	// SetBootVars
	c.Check(s.bootloader.SetBootVarsCalls, Equals, 0)
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"), testutil.FileAbsent)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemRemodelValidationSet(c *C) {
	// this test is mainly to make sure that the code that creates a recovery
	// system is able to properly fetch validation set assertions. both
	// assertions at an unconstrained sequence and a pinned sequence number.
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()

	tss, err := devicestate.CreateRecoverySystemTasks(s.state, "1234", nil, nil, devicestate.CreateRecoverySystemOptions{
		TestSystem: true,
	})
	c.Assert(err, IsNil)
	tsks := tss.Tasks()
	c.Check(tsks, HasLen, 2)
	tskCreate := tsks[0]
	tskFinalize := tsks[1]
	c.Assert(tskCreate.Summary(), Matches, `Create recovery system with label "1234"`)
	c.Check(tskFinalize.Summary(), Matches, `Finalize recovery system with label "1234"`)

	var systemSetupData map[string]any
	err = tskCreate.Get("recovery-system-setup", &systemSetupData)
	c.Assert(err, IsNil)
	c.Assert(systemSetupData, DeepEquals, map[string]any{
		"label":       "1234",
		"directory":   filepath.Join(boot.InitramfsUbuntuSeedDir, "systems/1234"),
		"test-system": true,
	})
	// add the test tasks to the change
	chg := s.state.NewChange("create-recovery-system", "create recovery system")
	chg.AddAll(tss)

	// downloads are only accepted if the tasks are executed as part of
	// remodel, so procure a new model
	newModel := s.brands.Model("canonical", "pc-20", map[string]any{
		"architecture": "amd64",
		// UC20
		"grade": "dangerous",
		"base":  "core20",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel",
				"id":              s.ss.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]any{
				"name":            "pc",
				"id":              s.ss.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
		},
		"validation-sets": []any{
			map[string]any{
				"account-id": "canonical",
				"name":       "vset-1",
				"mode":       "enforce",
			},
			map[string]any{
				"account-id": "canonical",
				"name":       "vset-2",
				"sequence":   "2",
				"mode":       "enforce",
			},
		},
		"revision": "2",
	})

	chg.Set("new-model", string(asserts.Encode(newModel)))

	setSnaps := []any{
		map[string]any{
			"id":       snaptest.AssertedSnapID("some-snap"),
			"name":     "some-snap",
			"presence": "invalid",
		},
	}

	setOne := map[string]any{
		"series":       "16",
		"account-id":   "canonical",
		"authority-id": "canonical",
		"publisher-id": "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps":        setSnaps,
		"timestamp":    time.Now().Format(time.RFC3339),
		"revision":     "1",
	}

	setTwo := map[string]any{
		"series":       "16",
		"account-id":   "canonical",
		"authority-id": "canonical",
		"publisher-id": "canonical",
		"name":         "vset-2",
		"sequence":     "2",
		"snaps":        setSnaps,
		"timestamp":    time.Now().Format(time.RFC3339),
		"revision":     "1",
	}

	signer := s.brands.Signing("canonical")

	vsetOne, err := signer.Sign(asserts.ValidationSetType, setOne, nil, "")
	c.Check(err, IsNil)
	c.Check(assertstate.Add(s.state, vsetOne), IsNil)

	vsetTwo, err := signer.Sign(asserts.ValidationSetType, setTwo, nil, "")
	c.Check(err, IsNil)
	c.Check(assertstate.Add(s.state, vsetTwo), IsNil)

	s.mockStandardSnapsModeenvAndBootloaderState(c)

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()
	defer s.state.Unlock()

	c.Assert(chg.Err(), IsNil)
	c.Assert(tskCreate.Status(), Equals, state.WaitStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoStatus)
	// a reboot is expected
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})

	validateCore20Seed(c, "1234", newModel, s.storeSigning.Trusted)
	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "1234",
		"recovery_system_status": "try",
	})
	modeenvAfterCreate, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterCreate, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
		// try model is unset as its measured properties are identical
	})
	// verify that new files are tracked correctly
	expectedFilesLog := &bytes.Buffer{}
	// new snap files are logged in this order
	for _, fname := range []string{
		"snapd_4.snap", "pc-kernel_2.snap", "core20_3.snap", "pc_1.snap",
	} {
		fmt.Fprintln(expectedFilesLog, filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps", fname))
	}
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"),
		testutil.FileEquals, expectedFilesLog.String())

	// these things happen on snapd startup
	restart.MockPending(s.state, restart.RestartUnset)
	s.state.Set("tried-systems", []string{"1234"})
	s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	s.bootloader.SetBootVarsCalls = 0

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	// simulate a restart and run change to completion
	s.mockRestartAndSettle(c, s.state, chg)

	c.Assert(chg.Err(), IsNil)
	c.Check(chg.IsReady(), Equals, true)
	c.Assert(tskCreate.Status(), Equals, state.DoneStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoneStatus)

	// this would be part of a remodel so some state is cleaned up only at the end of remodel change
	var triedSystemsAfterFinalize []string
	err = s.state.Get("tried-systems", &triedSystemsAfterFinalize)
	c.Assert(err, IsNil)
	c.Check(triedSystemsAfterFinalize, DeepEquals, []string{"1234"})

	modeenvAfterFinalize, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterFinalize, testutil.JsonEquals, boot.Modeenv{
		Mode:           "run",
		Base:           "core20_3.snap",
		CurrentKernels: []string{"pc-kernel_2.snap"},
		// the system is kept in the current list
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		// but not promoted to good systems yet
		GoodRecoverySystems: []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})
	// since this is part of a remodel, we don't expect any more calls to
	// SetBootVars
	c.Check(s.bootloader.SetBootVarsCalls, Equals, 0)
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"), testutil.FileAbsent)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemRemodelDownloadingMissingSnap(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	fooSnap := snaptest.MakeTestSnapWithFiles(c, "name: foo\nversion: 1.0\nbase: core20", nil)
	s.state.Lock()
	defer s.state.Unlock()
	// fake downloads are a nop
	tSnapsup1 := s.state.NewTask("fake-download", "test task carrying snap setup")
	// both snaps are asserted
	snapsupFoo := snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{RealName: "foo", SnapID: s.ss.AssertedSnapID("foo"), Revision: snap.R(99)},
		SnapPath: fooSnap,
	}
	tSnapsup1.Set("snap-setup", snapsupFoo)

	tss, err := devicestate.CreateRecoverySystemTasks(s.state, "1234missingdownload", []string{tSnapsup1.ID()}, nil, devicestate.CreateRecoverySystemOptions{
		TestSystem: true,
	})
	c.Assert(err, IsNil)
	tsks := tss.Tasks()
	c.Check(tsks, HasLen, 2)
	tskCreate := tsks[0]
	tskFinalize := tsks[1]
	c.Assert(tskCreate.Summary(), Matches, `Create recovery system with label "1234missingdownload"`)
	c.Check(tskFinalize.Summary(), Matches, `Finalize recovery system with label "1234missingdownload"`)
	var systemSetupData map[string]any
	err = tskCreate.Get("recovery-system-setup", &systemSetupData)
	c.Assert(err, IsNil)
	c.Assert(systemSetupData, DeepEquals, map[string]any{
		"label":            "1234missingdownload",
		"directory":        filepath.Join(boot.InitramfsUbuntuSeedDir, "systems/1234missingdownload"),
		"snap-setup-tasks": []any{tSnapsup1.ID()},
		"test-system":      true,
	})
	tss.WaitFor(tSnapsup1)
	// add the test task to the change
	chg := s.state.NewChange("create-recovery-system", "create recovery system")
	chg.AddTask(tSnapsup1)
	chg.AddAll(tss)

	// downloads are only accepted if the tasks are executed as part of
	// remodel, so procure a new model
	newModel := s.brands.Model("canonical", "pc-20", map[string]any{
		"architecture": "amd64",
		// UC20
		"grade": "dangerous",
		"base":  "core20",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel",
				"id":              s.ss.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]any{
				"name":            "pc",
				"id":              s.ss.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
			// we have a download task for snap foo, but not for bar
			map[string]any{
				"name":     "bar",
				"presence": "required",
			},
		},
		"revision": "2",
	})
	chg.Set("new-model", string(asserts.Encode(newModel)))

	s.mockStandardSnapsModeenvAndBootloaderState(c)

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), ErrorMatches, `(?s).*cannot create a recovery system.*internal error: non-essential but required snap "bar" not present.`)
	c.Assert(tskCreate.Status(), Equals, state.ErrorStatus)
	c.Assert(tskFinalize.Status(), Equals, state.HoldStatus)
	// a reboot is expected
	c.Check(s.restartRequests, HasLen, 0)
	// single bootloader call to clear any recovery system variables
	c.Check(s.bootloader.SetBootVarsCalls, Equals, 1)
	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	// system directory was removed
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems/1234missingdownload"), testutil.FileAbsent)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemUndoNoTestSystem(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	previousDefault := devicestate.DefaultRecoverySystem{
		System:   "previous",
		Model:    "model",
		BrandID:  "brand",
		Revision: 1,
	}
	s.state.Set("default-recovery-system", previousDefault)

	chg, err := devicestate.CreateRecoverySystem(s.state, "1234undo", devicestate.CreateRecoverySystemOptions{
		MarkDefault: true,
	})
	c.Assert(err, IsNil)
	c.Assert(chg, NotNil)
	tsks := chg.Tasks()
	c.Check(tsks, HasLen, 1)
	tskCreate := tsks[0]
	terr := s.state.NewTask("error-trigger", "provoking total undo")
	terr.WaitFor(tskCreate)
	chg.AddTask(terr)

	s.mockStandardSnapsModeenvAndBootloaderState(c)
	s.bootloader.SetBootVarsCalls = 0

	snaptest.PopulateDir(filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps"), [][]string{
		{"core20_10.snap", "canary"},
		{"some-snap_1.snap", "canary"},
	})

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), ErrorMatches, "(?s)cannot perform the following tasks.* provoking total undo.*")
	c.Assert(tskCreate.Status(), Equals, state.UndoneStatus)
	// a reboot is not expected
	c.Check(s.restartRequests, HasLen, 0)

	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})

	modeenvAfterCreate, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterCreate, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})

	var triedSystemsAfter []string
	err = s.state.Get("tried-systems", &triedSystemsAfter)
	c.Assert(err, testutil.ErrorIs, state.ErrNoState)

	// expect 2 calls to bootloader.SetBootVars: one for do, one for undo
	c.Check(s.bootloader.SetBootVarsCalls, Equals, 2)

	// system directory was removed
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems/1234undo"), testutil.FileAbsent)
	// only the canary files are left now
	p, err := filepath.Glob(filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/*"))
	c.Assert(err, IsNil)
	c.Check(p, DeepEquals, []string{
		filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/core20_10.snap"),
		filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/some-snap_1.snap"),
	})

	var defaultSystem devicestate.DefaultRecoverySystem
	err = s.state.Get("default-recovery-system", &defaultSystem)
	c.Assert(err, IsNil)
	c.Check(defaultSystem, DeepEquals, previousDefault)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemUndoTestSystem(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	previousDefault := devicestate.DefaultRecoverySystem{
		System:   "previous",
		Model:    "model",
		BrandID:  "brand",
		Revision: 1,
	}
	s.state.Set("default-recovery-system", previousDefault)

	chg, err := devicestate.CreateRecoverySystem(s.state, "1234undo", devicestate.CreateRecoverySystemOptions{
		TestSystem:  true,
		MarkDefault: true,
	})
	c.Assert(err, IsNil)
	c.Assert(chg, NotNil)
	tsks := chg.Tasks()
	c.Check(tsks, HasLen, 2)
	tskCreate := tsks[0]
	tskFinalize := tsks[1]
	terr := s.state.NewTask("error-trigger", "provoking total undo")
	terr.WaitFor(tskFinalize)
	chg.AddTask(terr)

	s.mockStandardSnapsModeenvAndBootloaderState(c)

	snaptest.PopulateDir(filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps"), [][]string{
		{"core20_10.snap", "canary"},
		{"some-snap_1.snap", "canary"},
	})

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), IsNil)
	c.Assert(tskCreate.Status(), Equals, state.WaitStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoStatus)
	// a reboot is expected
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})
	// validity check asserted snaps location
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems/1234undo"), testutil.FilePresent)
	p, err := filepath.Glob(filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/*"))
	c.Assert(err, IsNil)
	c.Check(p, DeepEquals, []string{
		filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/core20_10.snap"),
		filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/core20_3.snap"),
		filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/pc-kernel_2.snap"),
		filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/pc_1.snap"),
		filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/snapd_4.snap"),
		filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/some-snap_1.snap"),
	})
	// do more extensive validation
	validateCore20Seed(c, "1234undo", s.model, s.storeSigning.Trusted)
	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "1234undo",
		"recovery_system_status": "try",
	})
	modeenvAfterCreate, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterCreate, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234undo"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})

	// these things happen on snapd startup
	restart.MockPending(s.state, restart.RestartUnset)
	s.state.Set("tried-systems", []string{"1234undo"})
	s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	s.bootloader.SetBootVarsCalls = 0

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	// simulate a restart and run change to completion
	s.mockRestartAndSettle(c, s.state, chg)

	c.Assert(chg.Err(), ErrorMatches, "(?s)cannot perform the following tasks.* provoking total undo.*")
	c.Check(chg.IsReady(), Equals, true)
	c.Assert(tskCreate.Status(), Equals, state.UndoneStatus)
	c.Assert(tskFinalize.Status(), Equals, state.UndoneStatus)

	var triedSystemsAfter []string
	err = s.state.Get("tried-systems", &triedSystemsAfter)
	c.Assert(err, testutil.ErrorIs, state.ErrNoState)

	modeenvAfterFinalize, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterFinalize, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})
	// expect 2 calls to bootloader.SetBootVars: one for do, one for undo
	c.Check(s.bootloader.SetBootVarsCalls, Equals, 2)
	// system directory was removed
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems/1234undo"), testutil.FileAbsent)
	// only the canary files are left now
	p, err = filepath.Glob(filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/*"))
	c.Assert(err, IsNil)
	c.Check(p, DeepEquals, []string{
		filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/core20_10.snap"),
		filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/some-snap_1.snap"),
	})

	var defaultSystem devicestate.DefaultRecoverySystem
	err = s.state.Get("default-recovery-system", &defaultSystem)
	c.Assert(err, IsNil)
	c.Check(defaultSystem, Equals, previousDefault)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemFinalizeErrsWhenSystemFailed(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()

	chg, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		TestSystem: true,
	})
	c.Assert(err, IsNil)
	c.Assert(chg, NotNil)
	tsks := chg.Tasks()
	c.Check(tsks, HasLen, 2)
	tskCreate := tsks[0]
	tskFinalize := tsks[1]
	terr := s.state.NewTask("error-trigger", "provoking total undo")
	terr.WaitFor(tskFinalize)
	chg.AddTask(terr)

	s.mockStandardSnapsModeenvAndBootloaderState(c)

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), IsNil)
	c.Assert(tskCreate.Status(), Equals, state.WaitStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoStatus)
	// a reboot is expected
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})

	validateCore20Seed(c, "1234", s.model, s.storeSigning.Trusted)
	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "1234",
		"recovery_system_status": "try",
	})
	modeenvAfterCreate, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterCreate, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})

	// these things happen on snapd startup
	restart.MockPending(s.state, restart.RestartUnset)
	// after reboot the relevant startup code identified that the tried
	// system failed to operate properly
	s.state.Set("tried-systems", []string{})
	s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	s.bootloader.SetBootVarsCalls = 0

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()
	defer s.state.Unlock()

	// 'create-recovery-system' is pending a restart
	s.mockRestartAndSettle(c, s.state, chg)

	c.Assert(chg.Err(), ErrorMatches, `(?s)cannot perform the following tasks.* Finalize recovery system with label "1234" \(cannot promote recovery system "1234": system has not been successfully tried\)`)
	c.Check(chg.IsReady(), Equals, true)
	c.Assert(tskCreate.Status(), Equals, state.UndoneStatus)
	c.Assert(tskFinalize.Status(), Equals, state.ErrorStatus)

	var triedSystemsAfter []string
	err = s.state.Get("tried-systems", &triedSystemsAfter)
	c.Assert(err, IsNil)
	c.Assert(triedSystemsAfter, HasLen, 0)

	modeenvAfterFinalize, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterFinalize, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})
	// no more calls to the bootloader
	c.Check(s.bootloader.SetBootVarsCalls, Equals, 0)
	// seed directory was removed
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems/1234"), testutil.FileAbsent)
	// all common snaps were cleaned up
	p, err := filepath.Glob(filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/*"))
	c.Assert(err, IsNil)
	c.Check(p, HasLen, 0)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemErrCleanup(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()

	chg, err := devicestate.CreateRecoverySystem(s.state, "1234error", devicestate.CreateRecoverySystemOptions{
		TestSystem: true,
	})
	c.Assert(err, IsNil)
	c.Assert(chg, NotNil)
	tsks := chg.Tasks()
	c.Check(tsks, HasLen, 2)
	tskCreate := tsks[0]
	tskFinalize := tsks[1]

	s.mockStandardSnapsModeenvAndBootloaderState(c)
	s.bootloader.SetBootVarsCalls = 0

	s.bootloader.SetErrFunc = func() error {
		c.Logf("boot calls: %v", s.bootloader.SetBootVarsCalls)
		// for simplicity error out only when we try to set the recovery
		// system variables in bootenv (and not in the cleanup path)
		if s.bootloader.SetBootVarsCalls == 1 {
			return fmt.Errorf("mock bootloader error")
		}
		return nil
	}

	snaptest.PopulateDir(filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps"), [][]string{
		{"core20_10.snap", "canary"},
		{"some-snap_1.snap", "canary"},
	})

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()
	defer s.state.Unlock()

	c.Assert(chg.Err(), ErrorMatches, `(?s)cannot perform the following tasks.* \(cannot attempt booting into recovery system "1234error": mock bootloader error\)`)
	c.Check(chg.IsReady(), Equals, true)
	c.Assert(tskCreate.Status(), Equals, state.ErrorStatus)
	c.Assert(tskFinalize.Status(), Equals, state.HoldStatus)

	c.Check(s.restartRequests, HasLen, 0)
	// validity check asserted snaps location
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems/1234error"), testutil.FileAbsent)
	p, err := filepath.Glob(filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/*"))
	c.Assert(err, IsNil)
	c.Check(p, DeepEquals, []string{
		filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/core20_10.snap"),
		filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/some-snap_1.snap"),
	})
	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	modeenvAfterCreate, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterCreate, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemReboot(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	chg, err := devicestate.CreateRecoverySystem(s.state, "1234reboot", devicestate.CreateRecoverySystemOptions{
		TestSystem: true,
	})
	c.Assert(err, IsNil)
	c.Assert(chg, NotNil)
	tsks := chg.Tasks()
	c.Check(tsks, HasLen, 2)
	tskCreate := tsks[0]
	tskFinalize := tsks[1]

	s.mockStandardSnapsModeenvAndBootloaderState(c)
	s.bootloader.SetBootVarsCalls = 0

	setBootVarsOk := true
	s.bootloader.SetErrFunc = func() error {
		c.Logf("boot calls: %v", s.bootloader.SetBootVarsCalls)
		if setBootVarsOk {
			return nil
		}
		return fmt.Errorf("unexpected call")
	}

	snaptest.PopulateDir(filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps"), [][]string{
		{"core20_10.snap", "canary"},
		{"some-snap_1.snap", "canary"},
	})

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	// so far so good
	c.Assert(chg.Err(), IsNil)
	c.Assert(tskCreate.Status(), Equals, state.WaitStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoStatus)
	// a reboot is expected
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})
	c.Check(s.bootloader.SetBootVarsCalls, Equals, 2)
	s.restartRequests = nil

	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems/1234reboot"), testutil.FilePresent)
	// since we can't inject a panic into the task and recover from it in
	// the tests, reset the task states to as state which we would have if
	// the system unexpectedly reboots before the task is marked as done
	tskCreate.SetStatus(state.DoStatus)
	tskFinalize.SetStatus(state.DoStatus)
	restart.MockPending(s.state, restart.RestartUnset)
	// we may have rebooted just before the task was marked as done, in
	// which case tried systems would be populated
	s.state.Set("tried-systems", []string{"1234undo"})
	s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	setBootVarsOk = false

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()
	defer s.state.Unlock()

	c.Assert(chg.Err(), ErrorMatches, `(?s)cannot perform the following tasks.* \(cannot create a recovery system with label "1234reboot" for pc-20: system "1234reboot" already exists\)`)
	c.Assert(tskCreate.Status(), Equals, state.ErrorStatus)
	c.Assert(tskFinalize.Status(), Equals, state.HoldStatus)
	c.Check(s.restartRequests, HasLen, 0)

	// recovery system was removed
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems/1234reboot"), testutil.FileAbsent)
	// and so were the new snaps
	p, err := filepath.Glob(filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/*"))
	c.Assert(err, IsNil)
	c.Check(p, DeepEquals, []string{
		filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/core20_10.snap"),
		filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps/some-snap_1.snap"),
	})
	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	modeenvAfterCreate, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterCreate, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})
	var triedSystems []string
	s.state.Get("tried-systems", &triedSystems)
	c.Check(triedSystems, HasLen, 0)
}

type systemSnapTrackingSuite struct {
	deviceMgrSystemsBaseSuite
}

var _ = Suite(&systemSnapTrackingSuite{})

func (s *systemSnapTrackingSuite) TestSnapFileTracking(c *C) {
	otherDir := c.MkDir()
	systemDir := filepath.Join(boot.InitramfsUbuntuSeedDir, "systems/1234")
	flog := filepath.Join(otherDir, "files-log")

	snaptest.PopulateDir(systemDir, [][]string{
		{"this-will-be-removed", "canary"},
		{"this-one-too", "canary"},
		{"this-one-stays", "canary"},
		{"snaps/to-be-removed", "canary"},
		{"snaps/this-one-stays", "canary"},
	})

	// complain loudly if the file is under unexpected location
	err := devicestate.LogNewSystemSnapFile(flog, filepath.Join(otherDir, "some-file"))
	c.Assert(err, ErrorMatches, `internal error: unexpected recovery system snap location ".*/some-file"`)
	c.Check(flog, testutil.FileAbsent)

	expectedContent := &bytes.Buffer{}

	for _, p := range []string{
		filepath.Join(systemDir, "this-will-be-removed"),
		filepath.Join(systemDir, "this-one-too"),
		filepath.Join(systemDir, "does-not-exist"),
		filepath.Join(systemDir, "snaps/to-be-removed"),
	} {
		err = devicestate.LogNewSystemSnapFile(flog, p)
		c.Check(err, IsNil)
		fmt.Fprintln(expectedContent, p)
		// logged content is accumulated
		c.Check(flog, testutil.FileEquals, expectedContent.String())
	}

	// add some empty spaces to log file, which should get ignored when purging
	f, err := os.OpenFile(flog, os.O_APPEND, 0644)
	c.Assert(err, IsNil)
	defer f.Close()
	fmt.Fprintln(f, "    ")
	fmt.Fprintln(f, "")
	// and double some entries
	fmt.Fprintln(f, filepath.Join(systemDir, "this-will-be-removed"))

	err = devicestate.PurgeNewSystemSnapFiles(flog)
	c.Assert(err, IsNil)

	// those are removed
	for _, p := range []string{
		filepath.Join(systemDir, "this-will-be-removed"),
		filepath.Join(systemDir, "this-one-too"),
		filepath.Join(systemDir, "snaps/to-be-removed"),
	} {
		c.Check(p, testutil.FileAbsent)
	}
	c.Check(filepath.Join(systemDir, "this-one-stays"), testutil.FileEquals, "canary")
	c.Check(filepath.Join(systemDir, "snaps/this-one-stays"), testutil.FileEquals, "canary")
}

func (s *systemSnapTrackingSuite) TestSnapFilePurgeWhenNoLog(c *C) {
	otherDir := c.MkDir()
	flog := filepath.Join(otherDir, "files-log")
	// purge is still happy even if log file does not exist
	err := devicestate.PurgeNewSystemSnapFiles(flog)
	c.Assert(err, IsNil)
}

type modelAndGadgetInfoSuite struct {
	deviceMgrSystemsBaseSuite
}

var _ = Suite(&modelAndGadgetInfoSuite{})

func (s *modelAndGadgetInfoSuite) SetUpTest(c *C) {
	classic := false
	s.deviceMgrBaseSuite.setupBaseTest(c, classic)
}

var mockGadgetUCYaml = `
volumes:
  pc:
    bootloader: grub
    schema: gpt
    structure:
      - name: ubuntu-seed
        role: system-seed
        filesystem: vfat
        type: EF,C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        size: 1200M
      - name: ubuntu-boot
        filesystem: ext4
        size: 750M
        type: 83,0FC63DAF-8483-4772-8E79-3D69D8477DE4
        role: system-boot
      - name: ubuntu-save
        size: 16M
        filesystem: ext4
        type: 83,0FC63DAF-8483-4772-8E79-3D69D8477DE4
        role: system-save
      - name: ubuntu-data
        filesystem: ext4
        size: 1G
        type: 83,0FC63DAF-8483-4772-8E79-3D69D8477DE4
        role: system-data
`

var mockGadgetUCYamlNoBootRole = `
volumes:
  pc:
    bootloader: grub
    schema: gpt
    structure:
      - name: ubuntu-seed
        role: system-seed
        filesystem: vfat
        type: EF,C12A7328-F81F-11D2-BA4B-00A0C93EC93B
        size: 1200M
      - name: ubuntu-boot
        filesystem: ext4
        size: 750M
        type: 83,0FC63DAF-8483-4772-8E79-3D69D8477DE4
      - name: ubuntu-save
        size: 16M
        filesystem: ext4
        type: 83,0FC63DAF-8483-4772-8E79-3D69D8477DE4
        role: system-save
      - name: ubuntu-data
        filesystem: ext4
        size: 1G
        type: 83,0FC63DAF-8483-4772-8E79-3D69D8477DE4
        role: system-data
`

func (s *modelAndGadgetInfoSuite) makeMockUC20SeedWithGadgetYaml(c *C, label, gadgetYaml string, isClassic bool, snapdVersionByType map[snap.Type]string) *asserts.Model {
	seed20 := &seedtest.TestingSeed20{
		SeedSnaps: seedtest.SeedSnaps{
			StoreSigning: s.storeSigning,
			Brands:       s.brands,
		},
		SeedDir: dirs.SnapSeedDir,
	}
	restore := seed.MockTrusted(seed20.StoreSigning.Trusted)
	s.AddCleanup(restore)

	assertstest.AddMany(s.storeSigning.Database, s.brands.AccountsAndKeys("my-brand")...)

	if snapdVersionByType == nil {
		snapdVersionByType = map[snap.Type]string{
			snap.TypeSnapd:  "1",
			snap.TypeKernel: "1",
		}
	}

	seed20.MakeAssertedSnap(c,
		"name: snapd\nversion: 1\ntype: snapd",
		[][]string{{"usr/lib/snapd/info", fmt.Sprintf("VERSION=%s", snapdVersionByType[snap.TypeSnapd])}},
		snap.R(1), "my-brand", s.storeSigning.Database)
	seed20.MakeAssertedSnap(c,
		"name: pc-kernel\nversion: 1\ntype: kernel",
		[][]string{{"snapd-info", fmt.Sprintf("VERSION=%s", snapdVersionByType[snap.TypeKernel])}},
		snap.R(1), "my-brand", s.storeSigning.Database)
	seed20.MakeAssertedSnap(c, "name: core20\nversion: 1\ntype: base", nil, snap.R(1), "my-brand", s.storeSigning.Database)
	seed20.MakeAssertedSnap(c, "name: optional-snap\nversion: 1\ntype: app\nbase: core20", nil, snap.R(1), "my-brand", s.storeSigning.Database)
	gadgetFiles := [][]string{
		{"meta/gadget.yaml", string(gadgetYaml)},
	}
	seed20.MakeAssertedSnap(c, "name: pc\nversion: 1\ntype: gadget\nbase: core20", gadgetFiles, snap.R(1), "my-brand", s.storeSigning.Database)

	headers := map[string]any{
		"display-name": "my fancy model",
		"architecture": "amd64",
		"base":         "core20",
		"snaps": []any{
			map[string]any{
				"name": "snapd",
				"id":   seed20.AssertedSnapID("snapd"),
				"type": "snapd",
			},
			map[string]any{
				"name":            "pc-kernel",
				"id":              seed20.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]any{
				"name":            "pc",
				"id":              seed20.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
			map[string]any{
				"name":            "optional-snap",
				"presence":        "optional",
				"id":              seed20.AssertedSnapID("optional-snap"),
				"default-channel": "20",
			}},
	}
	if isClassic {
		headers["classic"] = "true"
		headers["distribution"] = "ubuntu"
	}
	return seed20.MakeSeed(c, label, "my-brand", "my-model", headers, []*seedwriter.OptionsSnap{
		{
			Name: "optional-snap",
		},
	})
}

// representative sample of a list with details about preinstall check errors identified by secboot
var preinstallErrorDetails = []secboot.PreinstallErrorDetails{
	{
		Kind:    "tpm-hierarchies-owned",
		Message: "error with TPM2 device: one or more of the TPM hierarchies is already owned",
		Args: map[string]json.RawMessage{
			"with-auth-value":  json.RawMessage(`[1073741834]`),
			"with-auth-policy": json.RawMessage(`[1073741825]`),
		},
		Actions: []string{"reboot-to-fw-settings"},
	},
	{
		Kind:    "tpm-device-lockout",
		Message: "error with TPM2 device: TPM is in DA lockout mode",
		Args: map[string]json.RawMessage{
			"interval-duration": json.RawMessage(`7200000000000`),
			"total-duration":    json.RawMessage(`230400000000000`),
		},
		Actions: []string{"reboot-to-fw-settings"},
	},
}

type suiteWithAddCleanup interface {
	AddCleanup(func())
}

// mockHelperForEncryptionAvailabilityCheck simplifies controlling availability check error details returned by
// install.encryptionAvailabilityCheck. This function mocks both the specialized secboot.PreinstallCheck check
// (Ubuntu hybrid on Ubuntu installer >= 25.10) and the general secboot.CheckTPMKeySealingSupported check
// (Ubuntu hybrid on Ubuntu installer < 25.1 & Ubuntu Core).
//
// isSupportedUbuntuHybrid: modify system release information and place current boot images to simulate supported Ubuntu hybrid install
// hasTPM: indicates if we should simulate having a TPM (no error detected) or no TPM (some representative error)
func mockHelperForEncryptionAvailabilityCheck(s suiteWithAddCleanup, c *C, isSupportedUbuntuHybrid, hasTPM bool) {
	releaseInfo := &release.OS{
		ID:        "ubuntu*",
		VersionID: "24.04",
	}
	if isSupportedUbuntuHybrid {
		// preinstall check is supported for Ubuntu hybrid >= 25.10
		releaseInfo = &release.OS{
			ID:        "ubuntu",
			VersionID: "25.10",
		}
	}
	s.AddCleanup(release.MockReleaseInfo(releaseInfo))

	// create fake boot images for supported Ubuntu hybrid system
	for _, path := range []string{
		"cdrom/EFI/boot/bootXXX.efi",
		"cdrom/EFI/boot/grubXXX.efi",
		"cdrom/casper/vmlinuz",
	} {
		bootImagePath := filepath.Join(dirs.GlobalRootDir, path)
		bootImageDir := filepath.Dir(bootImagePath)
		err := os.MkdirAll(bootImageDir, 0755)
		c.Assert(err, IsNil)

		if isSupportedUbuntuHybrid {
			f, err := os.Create(bootImagePath)
			c.Assert(err, IsNil)
			f.Close()
		} else {
			err := os.Remove(bootImagePath)
			c.Assert(err == nil || os.IsNotExist(err), Equals, true)
		}
	}

	restore1 := install.MockSecbootPreinstallCheck(func(ctx context.Context, bootImagePaths []string) ([]secboot.PreinstallErrorDetails, error) {
		c.Assert(bootImagePaths, HasLen, 3)
		c.Assert(isSupportedUbuntuHybrid, Equals, true)
		if hasTPM {
			return nil, nil
		} else {
			return preinstallErrorDetails[:1], nil
		}
	})
	s.AddCleanup(restore1)

	restore2 := install.MockSecbootCheckTPMKeySealingSupported(func(tpmMode secboot.TPMProvisionMode) error {
		c.Assert(tpmMode != secboot.TPMProvisionNone, Equals, true)
		if hasTPM {
			return nil
		} else {
			return fmt.Errorf("cannot connect to TPM device")
		}
	})

	s.AddCleanup(restore2)
}

func (s *modelAndGadgetInfoSuite) makeMockUC20SeedWithLocalContainers(c *C, label, gadgetYaml string, snapdVersionByType map[snap.Type]string) *asserts.Model {
	seed20 := &seedtest.TestingSeed20{
		SeedSnaps: seedtest.SeedSnaps{
			StoreSigning: s.storeSigning,
			Brands:       s.brands,
		},
		SeedDir: dirs.SnapSeedDir,
	}
	restore := seed.MockTrusted(seed20.StoreSigning.Trusted)
	s.AddCleanup(restore)

	assertstest.AddMany(s.storeSigning.Database, s.brands.AccountsAndKeys("my-brand")...)

	if snapdVersionByType == nil {
		snapdVersionByType = map[snap.Type]string{
			snap.TypeSnapd:  "1",
			snap.TypeKernel: "1",
		}
	}

	seed20.MakeAssertedSnap(c,
		"name: snapd\nversion: 1\ntype: snapd",
		[][]string{{"usr/lib/snapd/info",
			fmt.Sprintf("VERSION=%s", snapdVersionByType[snap.TypeSnapd])}},
		snap.R(1), "my-brand", s.storeSigning.Database)
	seed20.MakeAssertedSnap(c, "name: core20\nversion: 1\ntype: base",
		nil, snap.R(1), "my-brand", s.storeSigning.Database)
	gadgetFiles := [][]string{
		{"meta/gadget.yaml", string(gadgetYaml)},
	}
	seed20.MakeAssertedSnap(c, "name: pc\nversion: 1\ntype: gadget\nbase: core20",
		gadgetFiles, snap.R(1), "my-brand", s.storeSigning.Database)

	compsSnapPath := snaptest.MakeTestSnapWithFiles(c,
		"name: pc-kernel\nversion: 1\ntype: kernel\ncomponents:\n  comp1:\n    type: kernel-modules\n", nil)
	compPath := snaptest.MakeTestComponent(c,
		"component: pc-kernel+comp1\ntype: kernel-modules\nversion: 1.0.2")

	return seed20.MakeSeedWithLocalComponents(c, label, "my-brand", "my-model", map[string]any{
		"display-name": "my model",
		"architecture": "amd64",
		"base":         "core20",
		"grade":        "dangerous",
		"snaps": []any{
			map[string]any{
				"name": "snapd",
				"id":   seed20.AssertedSnapID("snapd"),
				"type": "snapd",
			},
			map[string]any{
				"name":            "pc-kernel",
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]any{
				"name":            "pc",
				"id":              seed20.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
		},
	}, []*seedwriter.OptionsSnap{
		{
			Path: compsSnapPath,
		},
	}, map[string][]string{
		"pc-kernel": {
			compPath,
		},
	})
}

func (s *modelAndGadgetInfoSuite) testSystemAndGadgetAndEncryptionInfoHappy(c *C, isSupportedHybrid bool, info install.EncryptionSupportInfo) {
	isClassic := isSupportedHybrid
	fakeModel := s.makeMockUC20SeedWithGadgetYaml(c, "some-label", mockGadgetUCYaml, isClassic, nil)
	expectedGadgetInfo, err := gadget.InfoFromGadgetYaml([]byte(mockGadgetUCYaml), fakeModel)
	c.Assert(err, IsNil)

	mockHelperForEncryptionAvailabilityCheck(s, c, isSupportedHybrid, false)

	system, gadgetInfo, encInfo, err := s.mgr.SystemAndGadgetAndEncryptionInfo("some-label")
	c.Assert(err, IsNil)
	c.Check(system, DeepEquals, &devicestate.System{
		Label:   "some-label",
		Model:   fakeModel,
		Brand:   s.brands.Account("my-brand"),
		Actions: defaultSystemActions,
		OptionalContainers: devicestate.OptionalContainers{
			Snaps: []string{"optional-snap"},
		},
	})
	c.Check(gadgetInfo.Volumes, DeepEquals, expectedGadgetInfo.Volumes)
	c.Check(encInfo, DeepEquals, &info)
}

func (s *modelAndGadgetInfoSuite) TestSystemAndGadgetAndEncryptionInfoNotSupportedHybridHappy(c *C) {
	// unsupported hybrid system uses general encryption availability check
	const isSupportedHybrid = false
	s.testSystemAndGadgetAndEncryptionInfoHappy(c, isSupportedHybrid, install.EncryptionSupportInfo{
		Available:          false,
		StorageSafety:      asserts.StorageSafetyPreferEncrypted,
		UnavailableWarning: "not encrypting device storage as checking TPM gave: cannot connect to TPM device",
	})
}

func (s *modelAndGadgetInfoSuite) TestSystemAndGadgetAndEncryptionInfoSupportedHybridHappy(c *C) {
	// supported hybrid system uses specialized encryption availability check
	const isSupportedHybrid = true
	s.testSystemAndGadgetAndEncryptionInfoHappy(c, isSupportedHybrid, install.EncryptionSupportInfo{
		Available:               false,
		StorageSafety:           asserts.StorageSafetyPreferEncrypted,
		UnavailableWarning:      "not encrypting device storage as checking TPM gave: error with TPM2 device: one or more of the TPM hierarchies is already owned",
		AvailabilityCheckErrors: preinstallErrorDetails[:1],
	})
}

func (s *modelAndGadgetInfoSuite) TestLoadSeedSetsRevisionForLocalContainers(c *C) {
	s.makeMockUC20SeedWithLocalContainers(c, "some-label", mockGadgetUCYaml, nil)

	sysSnaps, err := devicestate.LoadSystemAndEssentialSnaps(s.mgr, "some-label", []snap.Type{snap.TypeSnapd, snap.TypeKernel, snap.TypeGadget}, "run")
	c.Assert(err, IsNil)
	localRev := snap.R(-1)
	c.Check(sysSnaps.InfosByType[snap.TypeKernel].SnapRevision(), Equals, localRev)
	c.Check(sysSnaps.CompsByType[snap.TypeKernel][0].Seed.CompSideInfo.Revision, Equals, localRev)
	c.Check(sysSnaps.CompsByType[snap.TypeKernel][0].Info.Revision, Equals, localRev)
}

func (s *modelAndGadgetInfoSuite) testSystemAndGadgetAndEncryptionInfoPassphraseSupport(c *C, snapdVersionByType map[snap.Type]string, hasPassphraseSupport bool) {
	isClassic := false
	fakeModel := s.makeMockUC20SeedWithGadgetYaml(c, "some-label", mockGadgetUCYaml, isClassic, snapdVersionByType)
	expectedGadgetInfo, err := gadget.InfoFromGadgetYaml([]byte(mockGadgetUCYaml), fakeModel)
	c.Assert(err, IsNil)

	mockHelperForEncryptionAvailabilityCheck(s, c, false, true)

	system, gadgetInfo, encInfo, err := s.mgr.SystemAndGadgetAndEncryptionInfo("some-label")
	c.Assert(err, IsNil)
	c.Check(system, DeepEquals, &devicestate.System{
		Label:   "some-label",
		Model:   fakeModel,
		Brand:   s.brands.Account("my-brand"),
		Actions: defaultSystemActions,
		OptionalContainers: devicestate.OptionalContainers{
			Snaps: []string{"optional-snap"},
		},
	})
	c.Check(gadgetInfo.Volumes, DeepEquals, expectedGadgetInfo.Volumes)
	c.Check(encInfo, DeepEquals, &install.EncryptionSupportInfo{
		Available:               true,
		Type:                    "cryptsetup",
		StorageSafety:           asserts.StorageSafetyPreferEncrypted,
		PassphraseAuthAvailable: hasPassphraseSupport,
	})
}

func (s *modelAndGadgetInfoSuite) TestSystemAndGadgetAndEncryptionInfoPassphraseSupportOldSnapd(c *C) {
	snapdVersionByType := map[snap.Type]string{
		snap.TypeSnapd:  "2.67",
		snap.TypeKernel: "2.68",
	}
	const hasPassphraseSupport = false
	s.testSystemAndGadgetAndEncryptionInfoPassphraseSupport(c, snapdVersionByType, hasPassphraseSupport)
}

func (s *modelAndGadgetInfoSuite) TestSystemAndGadgetAndEncryptionInfoPassphraseSupportOldKernel(c *C) {
	snapdVersionByType := map[snap.Type]string{
		snap.TypeSnapd:  "2.68",
		snap.TypeKernel: "2.67",
	}
	const hasPassphraseSupport = false
	s.testSystemAndGadgetAndEncryptionInfoPassphraseSupport(c, snapdVersionByType, hasPassphraseSupport)
}

func (s *modelAndGadgetInfoSuite) TestSystemAndGadgetAndEncryptionInfoPassphraseSupportAvailable(c *C) {
	snapdVersionByType := map[snap.Type]string{
		snap.TypeSnapd:  "2.68",
		snap.TypeKernel: "2.68",
	}
	const hasPassphraseSupport = true
	s.testSystemAndGadgetAndEncryptionInfoPassphraseSupport(c, snapdVersionByType, hasPassphraseSupport)
}

func (s *modelAndGadgetInfoSuite) TestSystemAndGadgetInfoErrorInvalidLabel(c *C) {
	_, _, _, err := s.mgr.SystemAndGadgetAndEncryptionInfo("invalid/label")
	c.Assert(err, ErrorMatches, `cannot open: invalid seed system label: "invalid/label"`)
}

func (s *modelAndGadgetInfoSuite) TestSystemAndGadgetInfoErrorNoSeedDir(c *C) {
	_, _, _, err := s.mgr.SystemAndGadgetAndEncryptionInfo("no-such-seed")
	c.Assert(err, ErrorMatches, `cannot load assertions for label "no-such-seed": no seed assertions`)
}

func (s *modelAndGadgetInfoSuite) TestSystemAndGadgetInfoErrorNoGadget(c *C) {
	isClassic := false
	s.makeMockUC20SeedWithGadgetYaml(c, "some-label", mockGadgetUCYaml, isClassic, nil)
	// break the seed by removing the gadget
	err := os.Remove(filepath.Join(dirs.SnapSeedDir, "snaps", "pc_1.snap"))
	c.Assert(err, IsNil)

	_, _, _, err = s.mgr.SystemAndGadgetAndEncryptionInfo("some-label")
	c.Assert(err, ErrorMatches, "cannot load essential snaps metadata: cannot stat snap:.*: no such file or directory")
}

func (s *modelAndGadgetInfoSuite) TestSystemAndGadgetInfoErrorWrongGadget(c *C) {
	isClassic := false
	s.makeMockUC20SeedWithGadgetYaml(c, "some-label", mockGadgetUCYaml, isClassic, nil)
	// break the seed by changing things
	err := os.WriteFile(filepath.Join(dirs.SnapSeedDir, "snaps", "pc_1.snap"), []byte(`content-changed`), 0644)
	c.Assert(err, IsNil)

	_, _, _, err = s.mgr.SystemAndGadgetAndEncryptionInfo("some-label")
	c.Assert(err, ErrorMatches, `cannot load essential snaps metadata: cannot validate "/.*/pc_1.snap".* wrong size`)
}

func (s *modelAndGadgetInfoSuite) TestSystemAndGadgetInfoErrorInvalidGadgetYaml(c *C) {
	isClassic := false
	s.makeMockUC20SeedWithGadgetYaml(c, "some-label", "", isClassic, nil)

	_, _, _, err := s.mgr.SystemAndGadgetAndEncryptionInfo("some-label")
	c.Assert(err, ErrorMatches, "reading gadget information: bootloader not declared in any volume")
}

func (s *modelAndGadgetInfoSuite) TestSystemAndGadgetInfoErrorNoSeed(c *C) {
	restore := release.MockOnClassic(true)
	defer restore()

	// create a new manager as the "isClassicBoot" information is cached
	mgr, err := devicestate.Manager(s.state, s.hookMgr, s.o.TaskRunner(), nil)
	c.Assert(err, IsNil)

	_, _, _, err = mgr.SystemAndGadgetAndEncryptionInfo("some-label")
	c.Assert(err, ErrorMatches, `cannot load assertions for label "some-label": no seed assertions`)
}

func (s *modelAndGadgetInfoSuite) TestSystemAndGadgetInfoBadClassicGadget(c *C) {
	restore := release.MockOnClassic(true)
	defer restore()
	isClassic := true
	s.makeMockUC20SeedWithGadgetYaml(c, "some-label", mockGadgetUCYamlNoBootRole, isClassic, nil)

	mockHelperForEncryptionAvailabilityCheck(s, c, true, true)

	_, _, _, err := s.mgr.SystemAndGadgetAndEncryptionInfo("some-label")
	c.Assert(err, ErrorMatches, `cannot validate gadget.yaml: system-boot and system-data roles are needed on classic`)
}

func fakeSnapID(name string) string {
	if id := naming.WellKnownSnapID(name); id != "" {
		return id
	}
	return snaptest.AssertedSnapID(name)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsSnapInvalid(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	vset1, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "snapd",
				"id":       fakeSnapID("snapd"),
				"revision": "12",
				"presence": "required",
			},
			map[string]any{
				"name":     "core22",
				"id":       fakeSnapID("core20"),
				"revision": "12",
				"presence": "required",
			},
			map[string]any{
				"name":     "pc",
				"id":       fakeSnapID("pc"),
				"revision": "12",
				"presence": "required",
			},
			map[string]any{
				"name":     "pc-kernel",
				"id":       fakeSnapID("pc-kernel"),
				"presence": "invalid",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	s.state.Lock()
	defer s.state.Unlock()

	_, err = devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		ValidationSets: []*asserts.ValidationSet{vset1.(*asserts.ValidationSet)},
	})
	c.Assert(err, ErrorMatches, "snap presence is marked invalid by validation set: pc-kernel")
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsConflict(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	vset1, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc",
				"id":       fakeSnapID("pc"),
				"revision": "12",
				"presence": "required",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	vset2, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-2",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc",
				"id":       fakeSnapID("pc"),
				"revision": "13",
				"presence": "required",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	s.state.Lock()
	defer s.state.Unlock()

	_, err = devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		ValidationSets: []*asserts.ValidationSet{vset1.(*asserts.ValidationSet), vset2.(*asserts.ValidationSet)},
	})
	c.Assert(err, testutil.ErrorIs, &snapasserts.ValidationSetsConflictError{})

	vSetErr := &snapasserts.ValidationSetsConflictError{}
	c.Check(errors.As(err, &vSetErr), Equals, true)
	c.Check(vSetErr.Snaps[fakeSnapID("pc")].Error(), Equals, `cannot constrain snap "pc" at different revisions 12 (canonical/vset-1), 13 (canonical/vset-2)`)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsConflictWithModel(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	s.model = s.makeModelAssertionInState(c, "canonical", "pc-20", map[string]any{
		"architecture": "amd64",
		"grade":        "dangerous",
		"base":         "core20",
		"revision":     "2",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel",
				"id":              s.ss.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]any{
				"name":            "pc",
				"id":              s.ss.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
			map[string]any{
				"name": "core20",
				"id":   s.ss.AssertedSnapID("core20"),
				"type": "base",
			},
			map[string]any{
				"name": "snapd",
				"id":   s.ss.AssertedSnapID("snapd"),
				"type": "snapd",
			},
		},
		"validation-sets": []any{
			map[string]any{
				"account-id": "canonical",
				"name":       "vset-model",
				"mode":       "enforce",
			},
		},
	})

	vsetModel, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-model",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc",
				"id":       fakeSnapID("pc"),
				"revision": "12",
				"presence": "required",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	assertstatetest.AddMany(s.state, vsetModel)
	assertstate.UpdateValidationSet(s.state, &assertstate.ValidationSetTracking{
		AccountID: "canonical",
		Name:      "vset-model",
		Mode:      assertstate.Enforce,
		Current:   1,
	})

	vset1, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc",
				"id":       fakeSnapID("pc"),
				"revision": "13",
				"presence": "required",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	_, err = devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		ValidationSets: []*asserts.ValidationSet{vset1.(*asserts.ValidationSet)},
	})
	c.Assert(err, testutil.ErrorIs, &snapasserts.ValidationSetsConflictError{})

	vSetErr := &snapasserts.ValidationSetsConflictError{}
	c.Check(errors.As(err, &vSetErr), Equals, true)
	c.Check(vSetErr.Snaps[fakeSnapID("pc")].Error(), Equals, `cannot constrain snap "pc" at different revisions 12 (canonical/vset-model), 13 (canonical/vset-1)`)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemNoTestSystemMarkDefault(c *C) {
	const markDefault = true
	s.testDeviceManagerCreateRecoverySystemNoTestSystem(c, markDefault)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemNoTestSystemNoMarkDefault(c *C) {
	const markDefault = false
	s.testDeviceManagerCreateRecoverySystemNoTestSystem(c, markDefault)
}

func (s *deviceMgrSystemsCreateSuite) testDeviceManagerCreateRecoverySystemNoTestSystem(c *C, markDefault bool) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	s.state.Set("refresh-privacy-key", "some-privacy-key")
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	chg, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		TestSystem:  false,
		MarkDefault: markDefault,
	})
	c.Assert(err, IsNil)
	c.Assert(chg, NotNil)

	tsks := chg.Tasks()
	// should be just the create system task
	c.Check(tsks, HasLen, 1)
	tskCreate := tsks[0]
	c.Assert(tskCreate.Summary(), Matches, `Create recovery system with label "1234"`)

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), IsNil)
	c.Assert(tskCreate.Status(), Equals, state.DoneStatus)

	// a reboot is NOT expected
	c.Check(s.restartRequests, HasLen, 0)

	validateCore20Seed(c, "1234", s.model, s.storeSigning.Trusted)
	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)

	// these values should not be set, since we're not actually going to try
	// anything
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})

	modeenvAfterFinalize, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterFinalize, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem", "1234"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})

	// expect 1 more call to SetBootVars when system is marked recovery capable
	c.Check(s.bootloader.SetBootVarsCalls, Equals, 2)

	// this file should be removed in the create-recovery's-system's cleanup
	// handler
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"), testutil.FileAbsent)

	checkForSnapsInSeed(c, "snapd_4.snap", "pc-kernel_2.snap", "core20_3.snap", "pc_1.snap")

	if markDefault {
		var defaultSystem devicestate.DefaultRecoverySystem
		err := s.state.Get("default-recovery-system", &defaultSystem)
		c.Assert(err, IsNil)

		c.Assert(defaultSystem.System, Equals, "1234")
		c.Assert(defaultSystem.Model, Equals, s.model.Model())
		c.Assert(defaultSystem.BrandID, Equals, s.model.BrandID())
	} else {
		var defaultSystem devicestate.DefaultRecoverySystem
		err := s.state.Get("default-recovery-system", &defaultSystem)
		c.Assert(err, testutil.ErrorIs, state.ErrNoState)
	}
}

func checkForSnapsInSeed(c *C, snaps ...string) {
	snapsDir := filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps")
	for _, snap := range snaps {
		c.Check(filepath.Join(snapsDir, snap), testutil.FilePresent)
	}
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsMarkDefault(c *C) {
	s.testDeviceManagerCreateRecoverySystemValidationSetsHappy(c, testCreateRecoverySystemValidationSetsOptions{
		MarkDefault: true,
	})
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsNoMarkDefault(c *C) {
	s.testDeviceManagerCreateRecoverySystemValidationSetsHappy(c, testCreateRecoverySystemValidationSetsOptions{})
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsOptionalSnap(c *C) {
	s.testDeviceManagerCreateRecoverySystemValidationSetsHappy(c, testCreateRecoverySystemValidationSetsOptions{
		RequireOptionalSnapInValidationSet: true,
	})
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsPreinstallOptionalSnap(c *C) {
	s.testDeviceManagerCreateRecoverySystemValidationSetsHappy(c, testCreateRecoverySystemValidationSetsOptions{
		PreInstallOptionalSnap: true,
	})
}

type testCreateRecoverySystemValidationSetsOptions struct {
	MarkDefault                        bool
	RequireOptionalSnapInValidationSet bool
	PreInstallOptionalSnap             bool
}

func (s *deviceMgrSystemsCreateSuite) testDeviceManagerCreateRecoverySystemValidationSetsHappy(c *C, opts testCreateRecoverySystemValidationSetsOptions) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	s.model = s.makeModelAssertionInState(c, "canonical", "pc-20", map[string]any{
		"architecture": "amd64",
		"grade":        "dangerous",
		"base":         "core20",
		"revision":     "2",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel",
				"id":              s.ss.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]any{
				"name":            "pc",
				"id":              s.ss.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
			map[string]any{
				"name": "core20",
				"id":   s.ss.AssertedSnapID("core20"),
				"type": "base",
			},
			map[string]any{
				"name": "snapd",
				"id":   s.ss.AssertedSnapID("snapd"),
				"type": "snapd",
			},
			map[string]any{
				"name":     "other-required",
				"id":       s.ss.AssertedSnapID("other-required"),
				"type":     "app",
				"presence": "optional",
			},
		},
		"validation-sets": []any{
			map[string]any{
				"account-id": "canonical",
				"name":       "vset-model",
				"mode":       "enforce",
			},
		},
	})

	vsetModel, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-model",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc",
				"id":       fakeSnapID("pc"),
				"presence": "required",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	assertstatetest.AddMany(s.state, vsetModel)
	assertstate.UpdateValidationSet(s.state, &assertstate.ValidationSetTracking{
		AccountID: "canonical",
		Name:      "vset-model",
		Mode:      assertstate.Enforce,
		Current:   1,
	})

	snapRevisions := map[string]snap.Revision{
		"pc":             snap.R(10),
		"pc-kernel":      snap.R(11),
		"core20":         snap.R(12),
		"snapd":          snap.R(13),
		"other-required": snap.R(14),
	}

	snapTypes := map[string]snap.Type{
		"pc":             snap.TypeGadget,
		"pc-kernel":      snap.TypeKernel,
		"core20":         snap.TypeBase,
		"snapd":          snap.TypeSnapd,
		"other-required": snap.TypeApp,
	}

	var validationSets []*asserts.ValidationSet

	vsetAssert, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc",
				"id":       fakeSnapID("pc"),
				"revision": snapRevisions["pc"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "pc-kernel",
				"id":       fakeSnapID("pc-kernel"),
				"revision": snapRevisions["pc-kernel"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "core20",
				"id":       fakeSnapID("core20"),
				"revision": snapRevisions["core20"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "snapd",
				"id":       fakeSnapID("snapd"),
				"revision": snapRevisions["snapd"].String(),
				"presence": "required",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	validationSets = append(validationSets, vsetAssert.(*asserts.ValidationSet))

	if opts.PreInstallOptionalSnap {
		s.makeSnapInState(c, "other-required", snapRevisions["other-required"], nil, nil)
	}

	if opts.RequireOptionalSnapInValidationSet {
		vsetAssert, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
			"type":         "validation-set",
			"authority-id": "canonical",
			"series":       "16",
			"account-id":   "canonical",
			"name":         "vset-2",
			"sequence":     "1",
			"snaps": []any{
				map[string]any{
					"name":     "other-required",
					"id":       fakeSnapID("other-required"),
					"revision": snapRevisions["other-required"].String(),
					"presence": "required",
				},
			},
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}, nil, "")
		c.Assert(err, IsNil)

		validationSets = append(validationSets, vsetAssert.(*asserts.ValidationSet))
	}

	s.o.TaskRunner().AddHandler("mock-validate", func(task *state.Task, _ *tomb.Tomb) error {
		st := task.State()
		st.Lock()
		defer st.Unlock()

		snapsup, err := snapstate.TaskSnapSetup(task)
		c.Assert(err, IsNil)

		s.setupSnapDeclForNameAndID(c, snapsup.SideInfo.RealName, snapsup.SideInfo.SnapID, "canonical")
		s.setupSnapRevisionForFileAndID(
			c, snapsup.BlobPath(), snapsup.SideInfo.SnapID, "canonical", snapRevisions[snapsup.SideInfo.RealName],
		)

		return nil
	}, nil)

	s.o.TaskRunner().AddHandler("mock-download", func(task *state.Task, _ *tomb.Tomb) error {
		st := task.State()
		st.Lock()
		defer st.Unlock()

		snapsup, err := snapstate.TaskSnapSetup(task)
		c.Assert(err, IsNil)
		var path string
		var files [][]string
		switch snapsup.Type {
		case snap.TypeBase:
			path = snaptest.MakeTestSnapWithFiles(
				c,
				fmt.Sprintf("name: %s\nversion: 1.0\ntype: %s",
					snapsup.SideInfo.RealName,
					snapsup.Type,
				),
				nil,
			)
		case snap.TypeGadget:
			files = [][]string{
				{"meta/gadget.yaml", uc20gadgetYaml},
			}
			fallthrough
		default:
			path = snaptest.MakeTestSnapWithFiles(
				c,
				fmt.Sprintf("name: %s\nversion: 1.0\nbase: %s\ntype: %s",
					snapsup.SideInfo.RealName,
					snapsup.Base,
					snapsup.Type,
				),
				files,
			)
		}

		err = os.Rename(path, filepath.Join(dirs.SnapBlobDir, fmt.Sprintf("%s_%s.snap", snapsup.SideInfo.RealName, snapsup.Revision().String())))
		c.Assert(err, IsNil)
		return nil
	}, nil)

	devicestate.MockSnapstateDownload(func(
		ctx context.Context, st *state.State, name string, components []string, blobDirectory string, revOpts snapstate.RevisionOptions, opts snapstate.Options) (*state.TaskSet, *snap.Info, error,
	) {
		expectedRev, ok := snapRevisions[name]
		if !ok {
			return nil, nil, fmt.Errorf("unexpected snap name %q", name)
		}

		c.Check(revOpts.Revision.Unset(), Equals, true)

		tDownload := s.state.NewTask("mock-download", fmt.Sprintf("Download %s to track %s", name, revOpts.Channel))

		si := &snap.SideInfo{
			RealName: name,
			Revision: expectedRev,
			SnapID:   fakeSnapID(name),
		}
		tDownload.Set("snap-setup", &snapstate.SnapSetup{
			SideInfo: si,
			Base:     "core20",
			Type:     snapTypes[name],
		})

		_, info := snaptest.MakeTestSnapInfoWithFiles(c, snapYamls[name], snapFiles[name], si)

		opts.PrereqTracker.Add(info)

		tValidate := s.state.NewTask("mock-validate", fmt.Sprintf("Validate %s", name))
		tValidate.Set("snap-setup-task", tDownload.ID())

		tValidate.WaitFor(tDownload)
		ts := state.NewTaskSet(tDownload, tValidate)
		ts.MarkEdge(tDownload, snapstate.SnapSetupEdge)
		ts.MarkEdge(tValidate, snapstate.LastBeforeLocalModificationsEdge)
		return ts, info, nil
	})

	s.state.Set("refresh-privacy-key", "some-privacy-key")
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	chg, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		ValidationSets: validationSets,
		TestSystem:     true,
		MarkDefault:    opts.MarkDefault,
	})
	c.Assert(err, IsNil)
	c.Assert(chg, NotNil)
	tsks := chg.Tasks()

	snapCount := 4
	if opts.RequireOptionalSnapInValidationSet {
		snapCount++
	}
	// 2*snapCount snaps (download + validate) + create system + finalize system
	c.Check(tsks, HasLen, (2*snapCount)+2)

	tskCreate := tsks[0]
	tskFinalize := tsks[1]
	c.Assert(tskCreate.Summary(), Matches, `Create recovery system with label "1234"`)
	c.Check(tskFinalize.Summary(), Matches, `Finalize recovery system with label "1234"`)

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), IsNil)
	c.Assert(tskCreate.Status(), Equals, state.WaitStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoStatus)

	// a reboot is expected
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})

	var runModeSnaps []string
	if opts.RequireOptionalSnapInValidationSet || opts.PreInstallOptionalSnap {
		runModeSnaps = []string{"other-required"}
	}
	validateCore20Seed(c, "1234", s.model, s.storeSigning.Trusted, runModeSnaps...)

	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "1234",
		"recovery_system_status": "try",
	})
	modeenvAfterCreate, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterCreate, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})

	// verify that new files are tracked correctly
	expectedFiles := []string{"snapd_13.snap", "pc-kernel_11.snap", "core20_12.snap", "pc_10.snap"}
	if opts.RequireOptionalSnapInValidationSet || opts.PreInstallOptionalSnap {
		expectedFiles = append(expectedFiles, "other-required_14.snap")
	}

	expectedFilesLog := &bytes.Buffer{}
	for _, fname := range expectedFiles {
		fmt.Fprintln(expectedFilesLog, filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps", fname))
	}

	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"),
		testutil.FileEquals, expectedFilesLog.String())

	// these things happen on snapd startup
	restart.MockPending(s.state, restart.RestartUnset)
	s.state.Set("tried-systems", []string{"1234"})
	s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	s.bootloader.SetBootVarsCalls = 0

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	// simulate a restart and run change to completion
	s.mockRestartAndSettle(c, s.state, chg)

	c.Assert(chg.Err(), IsNil)
	c.Check(chg.IsReady(), Equals, true)
	c.Assert(tskCreate.Status(), Equals, state.DoneStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoneStatus)

	var triedSystemsAfterFinalize []string
	err = s.state.Get("tried-systems", &triedSystemsAfterFinalize)
	c.Assert(err, testutil.ErrorIs, state.ErrNoState)

	modeenvAfterFinalize, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterFinalize, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem", "1234"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})

	// expect 1 more call to bootloader.SetBootVars, since we're marking this
	// system as seeded
	c.Check(s.bootloader.SetBootVarsCalls, Equals, 1)
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"), testutil.FileAbsent)

	if opts.MarkDefault {
		var defaultSystem devicestate.DefaultRecoverySystem
		err := s.state.Get("default-recovery-system", &defaultSystem)
		c.Assert(err, IsNil)

		c.Assert(defaultSystem.System, Equals, "1234")
		c.Assert(defaultSystem.Model, Equals, s.model.Model())
		c.Assert(defaultSystem.BrandID, Equals, s.model.BrandID())
	} else {
		var defaultSystem devicestate.DefaultRecoverySystem
		err := s.state.Get("default-recovery-system", &defaultSystem)
		c.Assert(err, testutil.ErrorIs, state.ErrNoState)
	}
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsComponents(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	s.testDeviceManagerCreateRecoverySystemValidationSetsComponents(c, testCreateRecoverySystemValidationSetsComponentsOpts{
		kmodModelPresence: "required",
		kmodVsetPresence:  "required",
		blobs:             []string{"snapd_13.snap", "pc-kernel-with-kmods_11.snap", "pc-kernel-with-kmods+kmod_20.comp", "core20_12.snap", "pc_10.snap"},
		downloadedSnaps:   4,
		downloadedComps:   1,
	})
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsComponentsReuseFromOtherSnap(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	// snap doesn't fit in the validation sets, but the component does. we still
	// will re-download the component because we don't have the correct
	// snap-resource-pair assertion on the system.
	s.makeSnapInState(c, "pc-kernel-with-kmods", snap.R(10), nil, map[string]snap.Revision{
		"kmod": snap.R(20),
	})

	s.testDeviceManagerCreateRecoverySystemValidationSetsComponents(c, testCreateRecoverySystemValidationSetsComponentsOpts{
		kmodModelPresence: "required",
		kmodVsetPresence:  "required",
		blobs:             []string{"snapd_13.snap", "pc-kernel-with-kmods_11.snap", "pc-kernel-with-kmods+kmod_20.comp", "core20_12.snap", "pc_10.snap"},
		downloadedSnaps:   4,
		downloadedComps:   1,
	})
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsComponentsRequiredInVsets(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	// should still download and install the component, despite the correct snap
	// being present
	s.makeSnapInState(c, "pc-kernel-with-kmods", snap.R(11), nil, nil)

	s.testDeviceManagerCreateRecoverySystemValidationSetsComponents(c, testCreateRecoverySystemValidationSetsComponentsOpts{
		kmodModelPresence: "optional",
		kmodVsetPresence:  "required",
		blobs:             []string{"snapd_13.snap", "pc-kernel-with-kmods_11.snap", "pc-kernel-with-kmods+kmod_20.comp", "core20_12.snap", "pc_10.snap"},
		downloadedSnaps:   3, // snapd, core20, pc
		downloadedComps:   1, // pc-kernel-with-kmods+kmod
	})
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsComponentsNoInstall(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	s.testDeviceManagerCreateRecoverySystemValidationSetsComponents(c, testCreateRecoverySystemValidationSetsComponentsOpts{
		kmodModelPresence: "optional",
		kmodVsetPresence:  "optional",
		blobs:             []string{"snapd_13.snap", "pc-kernel-with-kmods_11.snap", "core20_12.snap", "pc_10.snap"},
		downloadedSnaps:   4,
		downloadedComps:   0,
	})
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsComponentsAlreadyInstalledComponent(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	// snap and components are already installed, but this component revision is
	// wrong. everything should still happen as if the snap was not installed.
	s.makeSnapInState(c, "pc-kernel-with-kmods", snap.R(11), nil, map[string]snap.Revision{
		"kmod": snap.R(19),
	})

	s.testDeviceManagerCreateRecoverySystemValidationSetsComponents(c, testCreateRecoverySystemValidationSetsComponentsOpts{
		kmodModelPresence: "required",
		kmodVsetPresence:  "required",
		blobs:             []string{"snapd_13.snap", "pc-kernel-with-kmods_11.snap", "pc-kernel-with-kmods+kmod_20.comp", "core20_12.snap", "pc_10.snap"},
		downloadedSnaps:   3, // snapd, core20, pc
		downloadedComps:   1, // pc-kernel-with-kmods+kmod
	})
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsComponentsAlreadyInstalledComponentOptional(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	// even though the component is optional, we still download it since it is
	// installed on the current system.
	s.makeSnapInState(c, "pc-kernel-with-kmods", snap.R(11), nil, map[string]snap.Revision{
		"kmod": snap.R(19),
	})

	s.testDeviceManagerCreateRecoverySystemValidationSetsComponents(c, testCreateRecoverySystemValidationSetsComponentsOpts{
		kmodModelPresence: "optional",
		kmodVsetPresence:  "optional",
		blobs:             []string{"snapd_13.snap", "pc-kernel-with-kmods_11.snap", "pc-kernel-with-kmods+kmod_20.comp", "core20_12.snap", "pc_10.snap"},
		downloadedSnaps:   3, // snapd, core20, pc
		downloadedComps:   1, // pc-kernel-with-kmods+kmod
	})
}

type testCreateRecoverySystemValidationSetsComponentsOpts struct {
	kmodModelPresence string
	kmodVsetPresence  string
	blobs             []string
	downloadedSnaps   int
	downloadedComps   int
}

func (s *deviceMgrSystemsCreateSuite) testDeviceManagerCreateRecoverySystemValidationSetsComponents(c *C, opts testCreateRecoverySystemValidationSetsComponentsOpts) {
	devicestate.SetBootOkRan(s.mgr, true)

	snapComponents := map[string][]string{
		"pc-kernel-with-kmods": {"kmod"},
	}

	s.model = s.makeModelAssertionInState(c, "canonical", "pc-20", map[string]any{
		"architecture": "amd64",
		"grade":        "dangerous",
		"base":         "core20",
		"revision":     "2",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel-with-kmods",
				"id":              s.ss.AssertedSnapID("pc-kernel-with-kmods"),
				"type":            "kernel",
				"default-channel": "20",
				"components": map[string]any{
					"kmod": map[string]any{
						"presence": opts.kmodModelPresence,
					},
					"other-kmod": map[string]any{
						"presence": "optional",
					},
				},
			},
			map[string]any{
				"name":            "pc",
				"id":              s.ss.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
			map[string]any{
				"name": "core20",
				"id":   s.ss.AssertedSnapID("core20"),
				"type": "base",
			},
			map[string]any{
				"name": "snapd",
				"id":   s.ss.AssertedSnapID("snapd"),
				"type": "snapd",
			},
		},
		"validation-sets": []any{
			map[string]any{
				"account-id": "canonical",
				"name":       "vset-model",
				"mode":       "enforce",
			},
		},
	})

	vsetModel, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-model",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc-kernel-with-kmods",
				"id":       fakeSnapID("pc-kernel-with-kmods"),
				"presence": "required",
				"revision": "11",
				"components": map[string]any{
					"kmod": map[string]any{
						"revision": "20",
						"presence": opts.kmodVsetPresence,
					},
				},
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	assertstatetest.AddMany(s.state, vsetModel)
	assertstate.UpdateValidationSet(s.state, &assertstate.ValidationSetTracking{
		AccountID: "canonical",
		Name:      "vset-model",
		Mode:      assertstate.Enforce,
		Current:   1,
	})

	snapRevisions := map[string]snap.Revision{
		"pc":                   snap.R(10),
		"pc-kernel-with-kmods": snap.R(11),
		"core20":               snap.R(12),
		"snapd":                snap.R(13),
	}

	componentRevisions := map[string]snap.Revision{
		"pc-kernel-with-kmods+kmod": snap.R(20),
	}

	componentTypes := map[string]snap.ComponentType{
		"pc-kernel-with-kmods+kmod": snap.KernelModulesComponent,
	}

	compsToTypes := func(snapName string) map[string]snap.ComponentType {
		res := make(map[string]snap.ComponentType)
		for _, comps := range snapComponents {
			for _, comp := range comps {
				res[comp] = componentTypes[naming.NewComponentRef(snapName, comp).String()]
			}
		}
		return res
	}

	snapTypes := map[string]snap.Type{
		"pc":                   snap.TypeGadget,
		"pc-kernel-with-kmods": snap.TypeKernel,
		"core20":               snap.TypeBase,
		"snapd":                snap.TypeSnapd,
	}

	var validationSets []*asserts.ValidationSet

	vsetAssert, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc",
				"id":       fakeSnapID("pc"),
				"revision": snapRevisions["pc"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "pc-kernel-with-kmods",
				"id":       fakeSnapID("pc-kernel-with-kmods"),
				"revision": snapRevisions["pc-kernel-with-kmods"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "core20",
				"id":       fakeSnapID("core20"),
				"revision": snapRevisions["core20"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "snapd",
				"id":       fakeSnapID("snapd"),
				"revision": snapRevisions["snapd"].String(),
				"presence": "required",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	validationSets = append(validationSets, vsetAssert.(*asserts.ValidationSet))

	s.o.TaskRunner().AddHandler("mock-validate", func(task *state.Task, _ *tomb.Tomb) error {
		st := task.State()
		st.Lock()
		defer st.Unlock()

		snapsup, err := snapstate.TaskSnapSetup(task)
		c.Assert(err, IsNil)

		s.setupSnapDeclForNameAndID(c, snapsup.SideInfo.RealName, snapsup.SideInfo.SnapID, "canonical")
		s.setupSnapRevisionForFileAndID(
			c, snapsup.BlobPath(), snapsup.SideInfo.SnapID, "canonical", snapRevisions[snapsup.SideInfo.RealName],
		)

		return nil
	}, nil)

	s.o.TaskRunner().AddHandler("mock-download", func(task *state.Task, _ *tomb.Tomb) error {
		st := task.State()
		st.Lock()
		defer st.Unlock()

		snapsup, err := snapstate.TaskSnapSetup(task)
		c.Assert(err, IsNil)
		var path string
		var files [][]string
		switch snapsup.Type {
		case snap.TypeBase:
			path = snaptest.MakeTestSnapWithFiles(
				c,
				withComponents(
					fmt.Sprintf("name: %s\nversion: 1.0\ntype: %s",
						snapsup.SideInfo.RealName,
						snapsup.Type,
					),
					compsToTypes(snapsup.InstanceName()),
				),
				nil,
			)
		case snap.TypeGadget:
			files = [][]string{
				{"meta/gadget.yaml", uc20gadgetYaml},
			}
			fallthrough
		default:
			path = snaptest.MakeTestSnapWithFiles(
				c,
				withComponents(
					fmt.Sprintf("name: %s\nversion: 1.0\nbase: %s\ntype: %s",
						snapsup.SideInfo.RealName,
						snapsup.Base,
						snapsup.Type,
					),
					compsToTypes(snapsup.InstanceName()),
				),
				files,
			)
		}

		err = os.Rename(path, filepath.Join(dirs.SnapBlobDir, fmt.Sprintf("%s_%s.snap", snapsup.SideInfo.RealName, snapsup.Revision().String())))
		c.Assert(err, IsNil)
		return nil
	}, nil)

	s.o.TaskRunner().AddHandler("mock-validate-component", func(task *state.Task, _ *tomb.Tomb) error {
		st := task.State()
		st.Lock()
		defer st.Unlock()

		compsup, snapsup, err := snapstate.TaskComponentSetup(task)
		c.Assert(err, IsNil)

		s.setupSnapResourceRevision(
			c,
			compsup.BlobPath(snapsup.InstanceName()),
			compsup.ComponentName(),
			snapsup.SideInfo.SnapID,
			"canonical",
			componentRevisions[compsup.CompSideInfo.Component.String()],
		)

		s.setupSnapResourcePair(
			c,
			compsup.ComponentName(),
			snapsup.SideInfo.SnapID,
			"canonical",
			componentRevisions[compsup.CompSideInfo.Component.String()],
			snapRevisions[snapsup.SideInfo.RealName],
		)

		s.setupSnapRevisionForFileAndID(
			c, snapsup.BlobPath(), snapsup.SideInfo.SnapID, "canonical", snapRevisions[snapsup.SideInfo.RealName],
		)

		return nil
	}, nil)

	s.o.TaskRunner().AddHandler("mock-download-component", func(task *state.Task, _ *tomb.Tomb) error {
		st := task.State()
		st.Lock()
		defer st.Unlock()

		compsup, snapsup, err := snapstate.TaskComponentSetup(task)
		c.Assert(err, IsNil)
		path := snaptest.MakeTestComponent(c, fmt.Sprintf(
			"component: %s\nversion: 1.0\ntype: %s\n",
			compsup.CompSideInfo.Component.String(),
			compsup.CompType,
		))

		err = os.Rename(path, compsup.BlobPath(snapsup.InstanceName()))
		c.Assert(err, IsNil)

		return nil
	}, nil)

	restore := devicestate.MockSnapstateDownloadComponents(func(
		ctx context.Context, st *state.State, name string, components []string, blobDirectory string, revOpts snapstate.RevisionOptions, opts snapstate.Options) (*state.TaskSet, error,
	) {
		c.Assert(revOpts.Revision, Equals, snapRevisions[name])

		si := &snap.SideInfo{
			RealName: name,
			Revision: snapRevisions[name],
			SnapID:   fakeSnapID(name),
		}

		snapsup := &snapstate.SnapSetup{
			SideInfo: si,
			Base:     "core20",
			Type:     snapTypes[name],
		}

		ts := state.NewTaskSet()
		var snapsupTask, prev *state.Task
		add := func(t *state.Task) {
			ts.AddTask(t)
			if prev == nil {
				t.Set("snap-setup", snapsup)
				snapsupTask = t
				ts.MarkEdge(t, snapstate.BeginEdge)
			} else {
				t.WaitFor(prev)
				t.Set("snap-setup-task", snapsupTask.ID())
			}
			prev = t
		}

		var compsupTaskIDs []string
		for _, comp := range components {
			cref := naming.NewComponentRef(name, comp)

			download := s.state.NewTask("mock-download-component", fmt.Sprintf("Download component %q", cref))
			download.Set("component-setup", &snapstate.ComponentSetup{
				CompSideInfo: &snap.ComponentSideInfo{
					Component: cref,
					Revision:  componentRevisions[cref.String()],
				},
				CompType: componentTypes[cref.String()],
			})
			compsupTaskIDs = append(compsupTaskIDs, download.ID())
			add(download)

			validate := s.state.NewTask("mock-validate-component", fmt.Sprintf("Validate component %q", cref))
			validate.Set("component-setup-task", download.ID())
			add(validate)
		}

		snapsupTask.Set("component-setup-tasks", compsupTaskIDs)
		ts.MarkEdge(snapsupTask, snapstate.SnapSetupEdge)
		ts.MarkEdge(prev, snapstate.LastBeforeLocalModificationsEdge)

		return ts, nil
	})
	defer restore()

	restore = devicestate.MockSnapstateDownload(func(
		ctx context.Context, st *state.State, name string, components []string, dir string, revOpts snapstate.RevisionOptions, opts snapstate.Options) (*state.TaskSet, *snap.Info, error,
	) {
		c.Assert(revOpts.Revision.Unset(), Equals, true)

		si := &snap.SideInfo{
			RealName: name,
			Revision: snapRevisions[name],
			SnapID:   fakeSnapID(name),
		}

		download := s.state.NewTask("mock-download", fmt.Sprintf("Download %s to track %s", name, revOpts.Channel))
		download.Set("snap-setup", &snapstate.SnapSetup{
			SideInfo: si,
			Base:     "core20",
			Type:     snapTypes[name],
		})

		ts := state.NewTaskSet(download)
		ts.MarkEdge(download, snapstate.BeginEdge)
		prev := download
		add := func(t *state.Task) {
			t.WaitFor(prev)
			t.Set("snap-setup-task", download.ID())
			ts.AddTask(t)
			prev = t
		}

		validate := s.state.NewTask("mock-validate", fmt.Sprintf("Validate %s", name))
		validate.Set("snap-setup-task", download.ID())
		add(validate)

		var compsupTaskIDs []string
		for _, comp := range components {
			cref := naming.NewComponentRef(name, comp)

			download := s.state.NewTask("mock-download-component", fmt.Sprintf("Download component %q", cref))
			download.Set("component-setup", &snapstate.ComponentSetup{
				CompSideInfo: &snap.ComponentSideInfo{
					Component: cref,
					Revision:  componentRevisions[cref.String()],
				},
				CompType: componentTypes[cref.String()],
			})
			compsupTaskIDs = append(compsupTaskIDs, download.ID())
			add(download)

			validate := s.state.NewTask("mock-validate-component", fmt.Sprintf("Validate component %q", cref))
			validate.Set("component-setup-task", download.ID())
			add(validate)
		}

		download.Set("component-setup-tasks", compsupTaskIDs)
		ts.MarkEdge(download, snapstate.SnapSetupEdge)
		ts.MarkEdge(prev, snapstate.LastBeforeLocalModificationsEdge)

		_, info := snaptest.MakeTestSnapInfoWithFiles(c, withComponents(snapYamls[name], compsToTypes(name)), snapFiles[name], si)
		opts.PrereqTracker.Add(info)

		return ts, info, nil
	})
	defer restore()

	s.state.Set("refresh-privacy-key", "some-privacy-key")
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	chg, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		ValidationSets: validationSets,
		TestSystem:     true,
		MarkDefault:    true,
	})
	c.Assert(err, IsNil)

	s.validateCreateRecoverySystemChange(c, chg, nil, opts.blobs, opts.downloadedSnaps, opts.downloadedComps)
}

func (s *deviceMgrSystemsCreateSuite) validateCreateRecoverySystemChange(
	c *C,
	chg *state.Change,
	runModeSnaps []string,
	blobs []string,
	downloadedSnaps, downloadedComps int,
) {
	tsks := chg.Tasks()

	// two per snap, two per comp, create system, finalize system
	c.Check(tsks, HasLen, (2*downloadedSnaps)+(2*downloadedComps)+2)

	tskCreate := tsks[0]
	tskFinalize := tsks[1]
	c.Assert(tskCreate.Summary(), Matches, `Create recovery system with label "1234"`)
	c.Check(tskFinalize.Summary(), Matches, `Finalize recovery system with label "1234"`)

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), IsNil)
	c.Assert(tskCreate.Status(), Equals, state.WaitStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoStatus)

	// a reboot is expected
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})

	validateCore20Seed(c, "1234", s.model, s.storeSigning.Trusted, runModeSnaps...)

	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "1234",
		"recovery_system_status": "try",
	})
	modeenvAfterCreate, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterCreate, testutil.JsonEquals, boot.Modeenv{
		Mode: "run",
		Base: "core20_3.snap",
		// the setup of this test suite uses a different kernel. this is correct
		// because that is the current kernel that is installed on this system
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})

	var expectedFilesLog bytes.Buffer
	for _, fname := range blobs {
		fmt.Fprintln(&expectedFilesLog, filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps", fname))
	}

	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"),
		testutil.FileEquals, expectedFilesLog.String())

	// these things happen on snapd startup
	restart.MockPending(s.state, restart.RestartUnset)
	s.state.Set("tried-systems", []string{"1234"})
	s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	s.bootloader.SetBootVarsCalls = 0

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	// simulate a restart and run change to completion
	s.mockRestartAndSettle(c, s.state, chg)

	c.Assert(chg.Err(), IsNil)
	c.Check(chg.IsReady(), Equals, true)
	c.Assert(tskCreate.Status(), Equals, state.DoneStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoneStatus)

	var triedSystemsAfterFinalize []string
	err = s.state.Get("tried-systems", &triedSystemsAfterFinalize)
	c.Assert(err, testutil.ErrorIs, state.ErrNoState)

	modeenvAfterFinalize, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterFinalize, testutil.JsonEquals, boot.Modeenv{
		Mode: "run",
		Base: "core20_3.snap",
		// the setup of this test suite uses a different kernel. this is correct
		// because that is the current kernel that is installed on this system
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem", "1234"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})

	// expect 1 more call to bootloader.SetBootVars, since we're marking this
	// system as seeded
	c.Check(s.bootloader.SetBootVarsCalls, Equals, 1)
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"), testutil.FileAbsent)

	var defaultSystem devicestate.DefaultRecoverySystem
	err = s.state.Get("default-recovery-system", &defaultSystem)
	c.Assert(err, IsNil)

	c.Assert(defaultSystem.System, Equals, "1234")
	c.Assert(defaultSystem.Model, Equals, s.model.Model())
	c.Assert(defaultSystem.BrandID, Equals, s.model.BrandID())
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsComponentsReuseInstalled(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	s.makeSnapInState(c, "pc-kernel-with-kmods", snap.R(11), nil, map[string]snap.Revision{
		"kmod": snap.R(22),
	})

	devicestate.SetBootOkRan(s.mgr, true)

	s.model = s.makeModelAssertionInState(c, "canonical", "pc-20", map[string]any{
		"architecture": "amd64",
		"grade":        "dangerous",
		"base":         "core20",
		"revision":     "2",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel-with-kmods",
				"id":              s.ss.AssertedSnapID("pc-kernel-with-kmods"),
				"type":            "kernel",
				"default-channel": "20",
				"components": map[string]any{
					"kmod": map[string]any{
						"presence": "required",
					},
				},
			},
			map[string]any{
				"name":            "pc",
				"id":              s.ss.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
			map[string]any{
				"name": "core20",
				"id":   s.ss.AssertedSnapID("core20"),
				"type": "base",
			},
			map[string]any{
				"name": "snapd",
				"id":   s.ss.AssertedSnapID("snapd"),
				"type": "snapd",
			},
		},
		"validation-sets": []any{
			map[string]any{
				"account-id": "canonical",
				"name":       "vset-model",
				"mode":       "enforce",
			},
		},
	})

	vset, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-model",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc-kernel-with-kmods",
				"id":       fakeSnapID("pc-kernel-with-kmods"),
				"presence": "required",
				"revision": "11",
				"components": map[string]any{
					"kmod": map[string]any{
						"revision": "22",
						"presence": "required",
					},
				},
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	assertstatetest.AddMany(s.state, vset)
	assertstate.UpdateValidationSet(s.state, &assertstate.ValidationSetTracking{
		AccountID: "canonical",
		Name:      "vset-model",
		Mode:      assertstate.Enforce,
		Current:   1,
	})

	s.state.Set("refresh-privacy-key", "some-privacy-key")
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	chg, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		TestSystem:  true,
		MarkDefault: true,
	})
	c.Assert(err, IsNil)
	c.Assert(chg, NotNil)
	tsks := chg.Tasks()

	// create system + finalize system
	c.Check(tsks, HasLen, 2)

	create, finalize := tsks[0], tsks[1]
	c.Check(create.Summary(), Matches, `Create recovery system with label "1234"`)
	c.Check(finalize.Summary(), Matches, `Finalize recovery system with label "1234"`)

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), IsNil)
	c.Assert(create.Status(), Equals, state.WaitStatus)
	c.Assert(finalize.Status(), Equals, state.DoStatus)

	// a reboot is expected
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})

	var runModeSnaps []string
	validateCore20Seed(c, "1234", s.model, s.storeSigning.Trusted, runModeSnaps...)

	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "1234",
		"recovery_system_status": "try",
	})
	modeenvAfterCreate, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterCreate, testutil.JsonEquals, boot.Modeenv{
		Mode: "run",
		Base: "core20_3.snap",
		// the setup of this test suite uses a different kernel. this is correct
		// because that is the current kernel that is installed on this system
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})

	// verify that new files are tracked correctly
	expectedFiles := []string{"snapd_4.snap", "pc-kernel-with-kmods_11.snap", "pc-kernel-with-kmods+kmod_22.comp", "core20_3.snap", "pc_1.snap"}

	var expectedFilesLog bytes.Buffer
	for _, fname := range expectedFiles {
		fmt.Fprintln(&expectedFilesLog, filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps", fname))
	}

	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"),
		testutil.FileEquals, expectedFilesLog.String())

	// these things happen on snapd startup
	restart.MockPending(s.state, restart.RestartUnset)
	s.state.Set("tried-systems", []string{"1234"})
	s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	s.bootloader.SetBootVarsCalls = 0

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	// simulate a restart and run change to completion
	s.mockRestartAndSettle(c, s.state, chg)

	c.Assert(chg.Err(), IsNil)
	c.Check(chg.IsReady(), Equals, true)
	c.Assert(create.Status(), Equals, state.DoneStatus)
	c.Assert(finalize.Status(), Equals, state.DoneStatus)

	var triedSystemsAfterFinalize []string
	err = s.state.Get("tried-systems", &triedSystemsAfterFinalize)
	c.Assert(err, testutil.ErrorIs, state.ErrNoState)

	modeenvAfterFinalize, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterFinalize, testutil.JsonEquals, boot.Modeenv{
		Mode: "run",
		Base: "core20_3.snap",
		// the setup of this test suite uses a different kernel. this is correct
		// because that is the current kernel that is installed on this system
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem", "1234"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})

	// expect 1 more call to bootloader.SetBootVars, since we're marking this
	// system as seeded
	c.Check(s.bootloader.SetBootVarsCalls, Equals, 1)
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"), testutil.FileAbsent)

	var defaultSystem devicestate.DefaultRecoverySystem
	err = s.state.Get("default-recovery-system", &defaultSystem)
	c.Assert(err, IsNil)

	c.Assert(defaultSystem.System, Equals, "1234")
	c.Assert(defaultSystem.Model, Equals, s.model.Model())
	c.Assert(defaultSystem.BrandID, Equals, s.model.BrandID())
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemOnlineWithLocalError(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	_, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		TestSystem: true,
		LocalSnaps: []snapstate.PathSnap{{SideInfo: &snap.SideInfo{}, Path: "/some/path"}},
	})
	c.Assert(err, ErrorMatches, "local snaps/components cannot be provided when creating a recovery system online")
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemOfflinePreinstalled(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	devicestate.MockSnapstateDownload(func(
		ctx context.Context, st *state.State, name string, components []string, blobDirectory string, revOpts snapstate.RevisionOptions, opts snapstate.Options) (*state.TaskSet, *snap.Info, error,
	) {
		c.Errorf("snapstate.Download called unexpectedly")
		return nil, nil, nil
	})

	s.state.Set("refresh-privacy-key", "some-privacy-key")
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	chg, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		TestSystem: true,
		Offline:    true,
	})
	c.Assert(err, IsNil)
	c.Assert(chg, NotNil)
	tsks := chg.Tasks()
	// create system + finalize system
	c.Check(tsks, HasLen, 2)
	tskCreate := tsks[0]
	tskFinalize := tsks[1]
	c.Assert(tskCreate.Summary(), Matches, `Create recovery system with label "1234"`)
	c.Check(tskFinalize.Summary(), Matches, `Finalize recovery system with label "1234"`)

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), IsNil)
	c.Assert(tskCreate.Status(), Equals, state.WaitStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoStatus)

	// a reboot is expected
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})

	validateCore20Seed(c, "1234", s.model, s.storeSigning.Trusted)
	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "1234",
		"recovery_system_status": "try",
	})
	modeenvAfterCreate, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterCreate, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})

	// verify that new files are tracked correctly
	expectedFilesLog := &bytes.Buffer{}
	for _, fname := range []string{"snapd_4.snap", "pc-kernel_2.snap", "core20_3.snap", "pc_1.snap"} {
		fmt.Fprintln(expectedFilesLog, filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps", fname))
	}

	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"),
		testutil.FileEquals, expectedFilesLog.String())

	// these things happen on snapd startup
	restart.MockPending(s.state, restart.RestartUnset)
	s.state.Set("tried-systems", []string{"1234"})
	s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	s.bootloader.SetBootVarsCalls = 0

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	// simulate a restart and run change to completion
	s.mockRestartAndSettle(c, s.state, chg)

	c.Assert(chg.Err(), IsNil)
	c.Check(chg.IsReady(), Equals, true)
	c.Assert(tskCreate.Status(), Equals, state.DoneStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoneStatus)

	var triedSystemsAfterFinalize []string
	err = s.state.Get("tried-systems", &triedSystemsAfterFinalize)
	c.Assert(err, testutil.ErrorIs, state.ErrNoState)

	modeenvAfterFinalize, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterFinalize, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem", "1234"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})

	// expect 1 more call to bootloader.SetBootVars, since we're marking this
	// system as seeded
	c.Check(s.bootloader.SetBootVarsCalls, Equals, 1)
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"), testutil.FileAbsent)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsOffline(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	snapRevisions := map[string]snap.Revision{
		"pc":        snap.R(10),
		"pc-kernel": snap.R(11),
		"core20":    snap.R(12),
		"snapd":     snap.R(13),
	}

	snapTypes := map[string]snap.Type{
		"pc":        snap.TypeGadget,
		"pc-kernel": snap.TypeKernel,
		"core20":    snap.TypeBase,
		"snapd":     snap.TypeSnapd,
	}

	vsetAssert, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc",
				"id":       fakeSnapID("pc"),
				"revision": snapRevisions["pc"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "pc-kernel",
				"id":       fakeSnapID("pc-kernel"),
				"revision": snapRevisions["pc-kernel"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "core20",
				"id":       fakeSnapID("core20"),
				"revision": snapRevisions["core20"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "snapd",
				"id":       fakeSnapID("snapd"),
				"revision": snapRevisions["snapd"].String(),
				"presence": "required",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	s.state.Lock()
	defer s.state.Unlock()

	assertstatetest.AddMany(s.state, vsetAssert)

	devicestate.MockSnapstateDownload(func(
		ctx context.Context, st *state.State, name string, components []string, blobDirectory string, revOpts snapstate.RevisionOptions, opts snapstate.Options) (*state.TaskSet, *snap.Info, error,
	) {
		c.Errorf("snapstate.Download called unexpectedly")
		return nil, nil, nil
	})

	localSnaps := make([]snapstate.PathSnap, 0, len(snapRevisions))
	for name, rev := range snapRevisions {
		var files [][]string
		var base string
		if snapTypes[name] == snap.TypeGadget {
			base = "core20"
			files = [][]string{
				{"meta/gadget.yaml", uc20gadgetYaml},
			}
		}

		si, path := createLocalSnap(c, name, fakeSnapID(name), rev.N, string(snapTypes[name]), base, files)

		// when we're creating a recovery system from snaps that are uploaded,
		// they get written to disk as tmp files. these don't have a .snap file
		// extension. this emulates that behavior.
		//
		// here we make sure that the seed writer allows us to create a seed
		// from snaps with invalid/missing file extensions.
		trimmed := strings.TrimSuffix(path, ".snap")
		err := os.Rename(path, trimmed)
		c.Assert(err, IsNil)
		path = trimmed

		localSnaps = append(localSnaps, snapstate.PathSnap{
			SideInfo: si,
			Path:     path,
		})

		s.setupSnapDeclForNameAndID(c, name, si.SnapID, "canonical")
		s.setupSnapRevisionForFileAndID(c, path, si.SnapID, "canonical", rev)
	}

	s.state.Set("refresh-privacy-key", "some-privacy-key")
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	chg, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		ValidationSets: []*asserts.ValidationSet{vsetAssert.(*asserts.ValidationSet)},
		LocalSnaps:     localSnaps,
		Offline:        true,
		TestSystem:     true,
	})
	c.Assert(err, IsNil)
	c.Assert(chg, NotNil)
	tsks := chg.Tasks()
	// create system + finalize system
	c.Check(tsks, HasLen, 2)
	tskCreate := tsks[0]
	tskFinalize := tsks[1]
	c.Assert(tskCreate.Summary(), Matches, `Create recovery system with label "1234"`)
	c.Check(tskFinalize.Summary(), Matches, `Finalize recovery system with label "1234"`)

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), IsNil)
	c.Assert(tskCreate.Status(), Equals, state.WaitStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoStatus)

	// a reboot is expected
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})

	validateCore20Seed(c, "1234", s.model, s.storeSigning.Trusted)
	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    "1234",
		"recovery_system_status": "try",
	})
	modeenvAfterCreate, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterCreate, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})

	// verify that new files are tracked correctly
	expectedFilesLog := &bytes.Buffer{}
	for _, fname := range []string{"snapd_13.snap", "pc-kernel_11.snap", "core20_12.snap", "pc_10.snap"} {
		fmt.Fprintln(expectedFilesLog, filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps", fname))
	}

	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"),
		testutil.FileEquals, expectedFilesLog.String())

	// these things happen on snapd startup
	restart.MockPending(s.state, restart.RestartUnset)
	s.state.Set("tried-systems", []string{"1234"})
	s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	s.bootloader.SetBootVarsCalls = 0

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	// simulate a restart and run change to completion
	s.mockRestartAndSettle(c, s.state, chg)

	c.Assert(chg.Err(), IsNil)
	c.Check(chg.IsReady(), Equals, true)
	c.Assert(tskCreate.Status(), Equals, state.DoneStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoneStatus)

	var triedSystemsAfterFinalize []string
	err = s.state.Get("tried-systems", &triedSystemsAfterFinalize)
	c.Assert(err, testutil.ErrorIs, state.ErrNoState)

	modeenvAfterFinalize, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterFinalize, testutil.JsonEquals, boot.Modeenv{
		Mode:                   "run",
		Base:                   "core20_3.snap",
		CurrentKernels:         []string{"pc-kernel_2.snap"},
		CurrentRecoverySystems: []string{"othersystem", "1234"},
		GoodRecoverySystems:    []string{"othersystem", "1234"},

		Model:          s.model.Model(),
		BrandID:        s.model.BrandID(),
		Grade:          string(s.model.Grade()),
		ModelSignKeyID: s.model.SignKeyID(),
	})

	// expect 1 more call to bootloader.SetBootVars, since we're marking this
	// system as seeded
	c.Check(s.bootloader.SetBootVarsCalls, Equals, 1)
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", "1234", "snapd-new-file-log"), testutil.FileAbsent)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsOfflineWithComponentsAllOptional(c *C) {
	s.testDeviceManagerCreateRecoverySystemValidationSetsOfflineWithComponents(c, testCreateRecoverySystemValidationSetsOfflineWithComponents{
		blobs:          []string{"snapd_4.snap", "pc-kernel-with-kmods_11.snap", "pc-kernel-with-kmods+kmod_22.comp", "core20_3.snap", "pc_1.snap"},
		snapsToProvide: []string{"pc-kernel-with-kmods"},
		componentsToProvide: []naming.ComponentRef{
			naming.NewComponentRef("pc-kernel-with-kmods", "kmod"),
		},
		kmodModelPresence: "optional",
		kmodVsetPresence:  "optional",
	})
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsOfflineWithComponentsRequiredInModel(c *C) {
	s.testDeviceManagerCreateRecoverySystemValidationSetsOfflineWithComponents(c, testCreateRecoverySystemValidationSetsOfflineWithComponents{
		blobs:          []string{"snapd_4.snap", "pc-kernel-with-kmods_11.snap", "pc-kernel-with-kmods+kmod_22.comp", "core20_3.snap", "pc_1.snap"},
		snapsToProvide: []string{"pc-kernel-with-kmods"},
		componentsToProvide: []naming.ComponentRef{
			naming.NewComponentRef("pc-kernel-with-kmods", "kmod"),
		},
		kmodModelPresence: "required",
		kmodVsetPresence:  "optional",
	})
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsOfflineWithComponentsRequiredInVsets(c *C) {
	s.testDeviceManagerCreateRecoverySystemValidationSetsOfflineWithComponents(c, testCreateRecoverySystemValidationSetsOfflineWithComponents{
		blobs:          []string{"snapd_4.snap", "pc-kernel-with-kmods_11.snap", "pc-kernel-with-kmods+kmod_22.comp", "core20_3.snap", "pc_1.snap"},
		snapsToProvide: []string{"pc-kernel-with-kmods"},
		componentsToProvide: []naming.ComponentRef{
			naming.NewComponentRef("pc-kernel-with-kmods", "kmod"),
		},
		kmodModelPresence: "optional",
		kmodVsetPresence:  "required",
	})
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsOfflineWithComponentsOptionalInstalled(c *C) {
	s.state.Lock()
	s.makeSnapInState(c, "pc-kernel-with-kmods", snap.R(11), nil, map[string]snap.Revision{
		"kmod": snap.R(22),
	})
	s.state.Unlock()

	s.testDeviceManagerCreateRecoverySystemValidationSetsOfflineWithComponents(c, testCreateRecoverySystemValidationSetsOfflineWithComponents{
		blobs: []string{"snapd_4.snap", "pc-kernel-with-kmods_11.snap", "pc-kernel-with-kmods+kmod_22.comp", "core20_3.snap", "pc_1.snap"},
		componentsToProvide: []naming.ComponentRef{
			naming.NewComponentRef("pc-kernel-with-kmods", "kmod"),
		},
		kmodModelPresence: "optional",
		kmodVsetPresence:  "optional",
	})
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsOfflineWithComponentsUseInstalled(c *C) {
	s.state.Lock()
	s.makeSnapInState(c, "pc-kernel-with-kmods", snap.R(11), nil, map[string]snap.Revision{
		"kmod": snap.R(22),
	})
	s.makeSnapInState(c, "snap-with-components", snap.R(12), nil, map[string]snap.Revision{
		"comp-1": snap.R(23),
	})
	s.state.Unlock()

	s.testDeviceManagerCreateRecoverySystemValidationSetsOfflineWithComponents(c, testCreateRecoverySystemValidationSetsOfflineWithComponents{
		blobs: []string{
			"snapd_4.snap", "pc-kernel-with-kmods_11.snap", "pc-kernel-with-kmods+kmod_22.comp",
			"core20_3.snap", "pc_1.snap", "snap-with-components_12.snap", "snap-with-components+comp-1_23.comp",
		},
		snapsToProvide: []string{"pc-kernel-with-kmods"},
		runModeSnaps:   []string{"snap-with-components"},
		componentsToProvide: []naming.ComponentRef{
			naming.NewComponentRef("pc-kernel-with-kmods", "kmod"),
		},
		kmodModelPresence: "optional",
		kmodVsetPresence:  "optional",
	})
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsOfflineWithComponentsUseLocalOverInstalled(c *C) {
	s.state.Lock()
	s.makeSnapInState(c, "pc-kernel-with-kmods", snap.R(11), nil, map[string]snap.Revision{
		"kmod": snap.R(22),
	})
	s.makeSnapInState(c, "snap-with-components", snap.R(12), nil, map[string]snap.Revision{
		"comp-1": snap.R(23),
	})
	s.state.Unlock()

	s.testDeviceManagerCreateRecoverySystemValidationSetsOfflineWithComponents(c, testCreateRecoverySystemValidationSetsOfflineWithComponents{
		blobs: []string{
			"snapd_4.snap", "pc-kernel-with-kmods_11.snap", "pc-kernel-with-kmods+kmod_22.comp",
			"core20_3.snap", "pc_1.snap", "snap-with-components_13.snap", "snap-with-components+comp-1_24.comp",
		},
		runModeSnaps:   []string{"snap-with-components"},
		snapsToProvide: []string{"pc-kernel-with-kmods", "snap-with-components"},
		componentsToProvide: []naming.ComponentRef{
			naming.NewComponentRef("pc-kernel-with-kmods", "kmod"),
			naming.NewComponentRef("snap-with-components", "comp-1"),
		},
		kmodModelPresence: "optional",
		kmodVsetPresence:  "optional",
	})
}

type testCreateRecoverySystemValidationSetsOfflineWithComponents struct {
	blobs               []string
	runModeSnaps        []string
	snapsToProvide      []string
	componentsToProvide []naming.ComponentRef
	kmodModelPresence   string
	kmodVsetPresence    string
}

func (s *deviceMgrSystemsCreateSuite) testDeviceManagerCreateRecoverySystemValidationSetsOfflineWithComponents(c *C, opts testCreateRecoverySystemValidationSetsOfflineWithComponents) {
	devicestate.SetBootOkRan(s.mgr, true)

	snapRevisions := map[string]snap.Revision{
		"pc-kernel-with-kmods": snap.R(11),
		"snap-with-components": snap.R(13),
	}

	snapComponents := map[string]map[string]snap.ComponentType{
		"pc-kernel-with-kmods": {
			"kmod": snap.KernelModulesComponent,
		},
		"snap-with-components": {
			"comp-1": snap.StandardComponent,
		},
	}

	componentRevisions := map[naming.ComponentRef]snap.Revision{
		naming.NewComponentRef("pc-kernel-with-kmods", "kmod"):   snap.R(22),
		naming.NewComponentRef("snap-with-components", "comp-1"): snap.R(24),
	}

	snapTypes := map[string]snap.Type{
		"pc-kernel-with-kmods": snap.TypeKernel,
		"snap-with-components": snap.TypeApp,
	}

	s.state.Lock()
	defer s.state.Unlock()

	s.model = s.makeModelAssertionInState(c, "canonical", "pc-20", map[string]any{
		"architecture": "amd64",
		"grade":        "dangerous",
		"base":         "core20",
		"revision":     "2",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel-with-kmods",
				"id":              s.ss.AssertedSnapID("pc-kernel-with-kmods"),
				"type":            "kernel",
				"default-channel": "20",
				"components": map[string]any{
					"kmod": map[string]any{
						"presence": opts.kmodModelPresence,
					},
					"other-kmod": map[string]any{
						"presence": "optional",
					},
				},
			},
			map[string]any{
				"name":            "pc",
				"id":              s.ss.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
			map[string]any{
				"name": "core20",
				"id":   s.ss.AssertedSnapID("core20"),
				"type": "base",
			},
			map[string]any{
				"name": "snapd",
				"id":   s.ss.AssertedSnapID("snapd"),
				"type": "snapd",
			},
			map[string]any{
				"name":     "snap-with-components",
				"id":       s.ss.AssertedSnapID("snap-with-components"),
				"type":     "app",
				"presence": "optional",
				"components": map[string]any{
					"comp-1": map[string]any{
						"presence": "optional",
					},
				},
			},
		},
	})

	vset, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc-kernel-with-kmods",
				"id":       fakeSnapID("pc-kernel-with-kmods"),
				"revision": snapRevisions["pc-kernel-with-kmods"].String(),
				"presence": "required",
				"components": map[string]any{
					"kmod": map[string]any{
						"presence": opts.kmodVsetPresence,
						"revision": componentRevisions[naming.NewComponentRef("pc-kernel-with-kmods", "kmod")].String(),
					},
				},
			},
			map[string]any{
				"name":     "snap-with-components",
				"id":       fakeSnapID("snap-with-components"),
				"presence": "optional",
				"components": map[string]any{
					"comp-1": map[string]any{
						"presence": "optional",
					},
				},
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	assertstatetest.AddMany(s.state, vset)

	localSnaps := make([]snapstate.PathSnap, 0, len(snapRevisions))
	for _, name := range opts.snapsToProvide {
		var files [][]string
		var base string
		switch snapTypes[name] {
		case snap.TypeGadget:
			files = [][]string{
				{"meta/gadget.yaml", uc20gadgetYaml},
			}
			fallthrough
		case snap.TypeApp:
			base = "core20"
		}
		if snapTypes[name] == snap.TypeGadget {
			base = "core20"
			files = [][]string{
				{"meta/gadget.yaml", uc20gadgetYaml},
			}
		}

		rev := snapRevisions[name]
		si := snap.SideInfo{
			RealName: name,
			Revision: rev,
			SnapID:   fakeSnapID(name),
		}

		yaml := fmt.Sprintf("name: %s\nversion: 1.0\ntype: %s", name, snapTypes[name])
		if base != "" {
			yaml += fmt.Sprintf("\nbase: %s", base)
		}
		yaml = withComponents(yaml, snapComponents[name])

		path := snaptest.MakeTestSnapWithFiles(c, yaml, files)

		s.setupSnapDeclForNameAndID(c, name, si.SnapID, "canonical")
		s.setupSnapRevisionForFileAndID(c, path, si.SnapID, "canonical", rev)

		localSnaps = append(localSnaps, snapstate.PathSnap{
			SideInfo: &si,
			Path:     path,
		})
	}

	localComponents := make([]snapstate.PathComponent, 0, len(opts.componentsToProvide))
	for _, cref := range opts.componentsToProvide {
		compRev := componentRevisions[cref]
		compType := snapComponents[cref.SnapName][cref.ComponentName]

		yaml := fmt.Sprintf("component: %s\nversion: 1.0\ntype: %s\n", cref, compType)
		compPath := snaptest.MakeTestComponent(c, yaml)

		snapID := fakeSnapID(cref.SnapName)
		s.setupSnapResourceRevision(c, compPath, cref.ComponentName, snapID, "canonical", compRev)
		s.setupSnapResourcePair(c, cref.ComponentName, snapID, "canonical", compRev, snapRevisions[cref.SnapName])

		localComponents = append(localComponents, snapstate.PathComponent{
			SideInfo: snap.NewComponentSideInfo(cref, compRev),
			Path:     compPath,
		})
	}

	s.state.Set("refresh-privacy-key", "some-privacy-key")
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	chg, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		ValidationSets:  []*asserts.ValidationSet{vset.(*asserts.ValidationSet)},
		LocalSnaps:      localSnaps,
		LocalComponents: localComponents,
		Offline:         true,
		TestSystem:      true,
		MarkDefault:     true,
	})
	c.Assert(err, IsNil)

	s.validateCreateRecoverySystemChange(c, chg, opts.runModeSnaps, opts.blobs, 0, 0)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsOfflineWrongRevisionSnap(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	// note that the revision for "pc" is different than the expected revisions
	providedRevisions := map[string]snap.Revision{
		"pc":        snap.R(100),
		"pc-kernel": snap.R(11),
		"core20":    snap.R(12),
		"snapd":     snap.R(13),
	}

	expectedRevisions := map[string]snap.Revision{
		"pc":        snap.R(10),
		"pc-kernel": snap.R(11),
		"core20":    snap.R(12),
		"snapd":     snap.R(13),
	}

	snapTypes := map[string]snap.Type{
		"pc":        snap.TypeGadget,
		"pc-kernel": snap.TypeKernel,
		"core20":    snap.TypeBase,
		"snapd":     snap.TypeSnapd,
	}

	vsetAssert, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc",
				"id":       fakeSnapID("pc"),
				"revision": expectedRevisions["pc"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "pc-kernel",
				"id":       fakeSnapID("pc-kernel"),
				"revision": expectedRevisions["pc-kernel"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "core20",
				"id":       fakeSnapID("core20"),
				"revision": expectedRevisions["core20"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "snapd",
				"id":       fakeSnapID("snapd"),
				"revision": expectedRevisions["snapd"].String(),
				"presence": "required",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	assertstatetest.AddMany(s.state, vsetAssert)

	localSnaps := make([]snapstate.PathSnap, 0, len(providedRevisions))
	for name, rev := range providedRevisions {
		si, path := createLocalSnap(c, name, fakeSnapID(name), rev.N, string(snapTypes[name]), "", nil)

		localSnaps = append(localSnaps, snapstate.PathSnap{
			SideInfo: si,
			Path:     path,
		})

		s.setupSnapDeclForNameAndID(c, name, si.SnapID, "canonical")
		s.setupSnapRevisionForFileAndID(c, path, si.SnapID, "canonical", rev)
	}

	s.mockStandardSnapsModeenvAndBootloaderState(c)

	_, err = devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		ValidationSets: []*asserts.ValidationSet{vsetAssert.(*asserts.ValidationSet)},
		LocalSnaps:     localSnaps,
		Offline:        true,
	})
	c.Assert(err, ErrorMatches, `snap "pc" does not match revision required by validation sets: 100 != 10`)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemOfflineMissingRequiredComponent(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	s.model = s.makeModelAssertionInState(c, "canonical", "pc-20", map[string]any{
		"architecture": "amd64",
		"grade":        "dangerous",
		"base":         "core24",
		"revision":     "2",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel-with-kmods",
				"id":              s.ss.AssertedSnapID("pc-kernel-with-kmods"),
				"type":            "kernel",
				"default-channel": "20",
				"components": map[string]any{
					"kmod": map[string]any{
						"presence": "required",
					},
				},
			},
			map[string]any{
				"name":            "pc",
				"id":              s.ss.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
			map[string]any{
				"name": "core24",
				"id":   s.ss.AssertedSnapID("core24"),
				"type": "base",
			},
			map[string]any{
				"name": "snapd",
				"id":   s.ss.AssertedSnapID("snapd"),
				"type": "snapd",
			},
		},
	})

	// note that the revision for "pc" is different than the expected revisions
	providedRevisions := map[string]snap.Revision{
		"pc":                   snap.R(100),
		"pc-kernel-with-kmods": snap.R(11),
		"core24":               snap.R(12),
		"snapd":                snap.R(13),
	}

	snapTypes := map[string]snap.Type{
		"pc":                   snap.TypeGadget,
		"pc-kernel-with-kmods": snap.TypeKernel,
		"core24":               snap.TypeBase,
		"snapd":                snap.TypeSnapd,
	}

	localSnaps := make([]snapstate.PathSnap, 0, len(providedRevisions))
	for name, rev := range providedRevisions {
		si, path := createLocalSnap(c, name, fakeSnapID(name), rev.N, string(snapTypes[name]), "", nil)

		localSnaps = append(localSnaps, snapstate.PathSnap{
			SideInfo: si,
			Path:     path,
		})

		s.setupSnapDeclForNameAndID(c, name, si.SnapID, "canonical")
		s.setupSnapRevisionForFileAndID(c, path, si.SnapID, "canonical", rev)
	}

	s.mockStandardSnapsModeenvAndBootloaderState(c)

	_, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		LocalSnaps: localSnaps,
		Offline:    true,
	})
	c.Assert(err, ErrorMatches, `missing component from local components provided for offline creation of recovery system: "pc-kernel-with-kmods\+kmod", rev unset`)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemOfflineInvalidComponentRevision(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	s.model = s.makeModelAssertionInState(c, "canonical", "pc-20", map[string]any{
		"architecture": "amd64",
		"grade":        "dangerous",
		"base":         "core24",
		"revision":     "2",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel-with-kmods",
				"id":              s.ss.AssertedSnapID("pc-kernel-with-kmods"),
				"type":            "kernel",
				"default-channel": "20",
				"components": map[string]any{
					"kmod": map[string]any{
						"presence": "required",
					},
				},
			},
			map[string]any{
				"name":            "pc",
				"id":              s.ss.AssertedSnapID("pc"),
				"type":            "gadget",
				"default-channel": "20",
			},
			map[string]any{
				"name": "core24",
				"id":   s.ss.AssertedSnapID("core24"),
				"type": "base",
			},
			map[string]any{
				"name": "snapd",
				"id":   s.ss.AssertedSnapID("snapd"),
				"type": "snapd",
			},
		},
	})

	vsetAssert, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc-kernel-with-kmods",
				"id":       fakeSnapID("pc-kernel-with-kmods"),
				"presence": "required",
				"revision": "11",
				"components": map[string]any{
					"kmod": map[string]any{
						"revision": "33",
						"presence": "required",
					},
				},
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	assertstatetest.AddMany(s.state, vsetAssert)

	// note that the revision for "pc" is different than the expected revisions
	providedRevisions := map[string]snap.Revision{
		"pc":                   snap.R(10),
		"pc-kernel-with-kmods": snap.R(11),
		"core24":               snap.R(12),
		"snapd":                snap.R(13),
	}

	snapTypes := map[string]snap.Type{
		"pc":                   snap.TypeGadget,
		"pc-kernel-with-kmods": snap.TypeKernel,
		"core24":               snap.TypeBase,
		"snapd":                snap.TypeSnapd,
	}

	localSnaps := make([]snapstate.PathSnap, 0, len(providedRevisions))
	for name, rev := range providedRevisions {
		si, path := createLocalSnap(c, name, fakeSnapID(name), rev.N, string(snapTypes[name]), "", nil)
		localSnaps = append(localSnaps, snapstate.PathSnap{
			SideInfo: si,
			Path:     path,
		})

		s.setupSnapDeclForNameAndID(c, name, si.SnapID, "canonical")
		s.setupSnapRevisionForFileAndID(c, path, si.SnapID, "canonical", rev)
	}

	snapID := fakeSnapID("pc-kernel-with-kmods")
	cref := naming.NewComponentRef("pc-kernel-with-kmods", "kmod")
	compRev := snap.R(22)
	compPath := snaptest.MakeTestComponent(c, "component: pc-kernel-with-kmods+kmod\nversion: 1.0\ntype: kernel-modules\n")
	s.setupSnapResourceRevision(c, compPath, "kmod", snapID, "canonical", compRev)
	s.setupSnapResourcePair(c, "kmod", snapID, "canonical", compRev, providedRevisions["pc-kernel-with-kmods"])

	localComponents := []snapstate.PathComponent{{
		SideInfo: snap.NewComponentSideInfo(cref, compRev),
		Path:     compPath,
	}}

	s.mockStandardSnapsModeenvAndBootloaderState(c)

	_, err = devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		ValidationSets:  []*asserts.ValidationSet{vsetAssert.(*asserts.ValidationSet)},
		LocalSnaps:      localSnaps,
		LocalComponents: localComponents,
		Offline:         true,
	})
	c.Assert(err, ErrorMatches, `component "pc-kernel-with-kmods\+kmod" does not match revision required by validation sets: 22 != 33`)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemMissingSnapIDFromModel(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	s.model = s.makeModelAssertionInState(c, "canonical", "pc-20", map[string]any{
		"architecture": "amd64",
		"grade":        "dangerous",
		"base":         "core20",
		"revision":     "10",
		"snaps": []any{
			map[string]any{
				"name":            "pc-kernel",
				"id":              s.ss.AssertedSnapID("pc-kernel"),
				"type":            "kernel",
				"default-channel": "20",
			},
			map[string]any{
				"name":            "pc",
				"type":            "gadget",
				"default-channel": "20",
			},
			map[string]any{
				"name": "core20",
				"id":   s.ss.AssertedSnapID("core20"),
				"type": "base",
			},
			map[string]any{
				"name": "snapd",
				"id":   s.ss.AssertedSnapID("snapd"),
				"type": "snapd",
			},
		},
	})

	snapRevisions := map[string]snap.Revision{
		"pc":        snap.R(100),
		"pc-kernel": snap.R(11),
		"core20":    snap.R(12),
		"snapd":     snap.R(13),
	}

	snapTypes := map[string]snap.Type{
		"pc":        snap.TypeGadget,
		"pc-kernel": snap.TypeKernel,
		"core20":    snap.TypeBase,
		"snapd":     snap.TypeSnapd,
	}

	localSnaps := make([]snapstate.PathSnap, 0, len(snapRevisions))
	for name, rev := range snapRevisions {
		si, path := createLocalSnap(c, name, fakeSnapID(name), rev.N, string(snapTypes[name]), "", nil)

		localSnaps = append(localSnaps, snapstate.PathSnap{
			SideInfo: si,
			Path:     path,
		})
	}

	s.mockStandardSnapsModeenvAndBootloaderState(c)

	_, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		LocalSnaps: localSnaps,
		Offline:    true,
	})
	c.Assert(err, ErrorMatches, `cannot create recovery system from model with snap that has no snap id: "pc"`)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemMissingSnapID(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	snapRevisions := map[string]snap.Revision{
		"pc":        snap.R(100),
		"pc-kernel": snap.R(11),
		"core20":    snap.R(12),
		"snapd":     snap.R(13),
	}

	snapTypes := map[string]snap.Type{
		"pc":        snap.TypeGadget,
		"pc-kernel": snap.TypeKernel,
		"core20":    snap.TypeBase,
		"snapd":     snap.TypeSnapd,
	}

	localSnaps := make([]snapstate.PathSnap, 0, len(snapRevisions))
	for name, rev := range snapRevisions {
		si, path := createLocalSnap(c, name, fakeSnapID(name), rev.N, string(snapTypes[name]), "", nil)

		if name == "pc" {
			si.SnapID = ""
		}

		localSnaps = append(localSnaps, snapstate.PathSnap{
			SideInfo: si,
			Path:     path,
		})
	}

	s.mockStandardSnapsModeenvAndBootloaderState(c)

	_, err := devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		LocalSnaps: localSnaps,
		Offline:    true,
	})
	c.Assert(err, ErrorMatches, `cannot create recovery system from provided snap that has no snap id: "pc"`)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsOfflineMissingSnap(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	// note that "pc" is missing. this snap won't be provided to
	// CreateRecoverySystem
	providedRevisions := map[string]snap.Revision{
		"pc-kernel": snap.R(11),
		"core20":    snap.R(12),
		"snapd":     snap.R(13),
	}

	expectedRevisions := map[string]snap.Revision{
		"pc":        snap.R(10),
		"pc-kernel": snap.R(11),
		"core20":    snap.R(12),
		"snapd":     snap.R(13),
	}

	snapTypes := map[string]snap.Type{
		"pc":        snap.TypeGadget,
		"pc-kernel": snap.TypeKernel,
		"core20":    snap.TypeBase,
		"snapd":     snap.TypeSnapd,
	}

	vsetAssert, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc",
				"id":       fakeSnapID("pc"),
				"revision": expectedRevisions["pc"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "pc-kernel",
				"id":       fakeSnapID("pc-kernel"),
				"revision": expectedRevisions["pc-kernel"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "core20",
				"id":       fakeSnapID("core20"),
				"revision": expectedRevisions["core20"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "snapd",
				"id":       fakeSnapID("snapd"),
				"revision": expectedRevisions["snapd"].String(),
				"presence": "required",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	assertstatetest.AddMany(s.state, vsetAssert)

	localSnaps := make([]snapstate.PathSnap, 0, len(providedRevisions))
	for name, rev := range providedRevisions {
		si, path := createLocalSnap(c, name, fakeSnapID(name), rev.N, string(snapTypes[name]), "", nil)

		localSnaps = append(localSnaps, snapstate.PathSnap{
			SideInfo: si,
			Path:     path,
		})

		s.setupSnapDeclForNameAndID(c, name, si.SnapID, "canonical")
		s.setupSnapRevisionForFileAndID(c, path, si.SnapID, "canonical", rev)
	}

	s.mockStandardSnapsModeenvAndBootloaderState(c)

	_, err = devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		ValidationSets: []*asserts.ValidationSet{vsetAssert.(*asserts.ValidationSet)},
		LocalSnaps:     localSnaps,
		Offline:        true,
	})
	c.Assert(err, ErrorMatches, `missing snap from local snaps provided for offline creation of recovery system: "pc", rev 10`)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsMissingPrereqs(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	snapRevisions := map[string]snap.Revision{
		"pc":        snap.R(10),
		"pc-kernel": snap.R(11),
		"core20":    snap.R(12),
		"snapd":     snap.R(13),
	}

	snapTypes := map[string]snap.Type{
		"pc":        snap.TypeGadget,
		"pc-kernel": snap.TypeKernel,
		"core20":    snap.TypeBase,
		"snapd":     snap.TypeSnapd,
	}

	vsetAssert, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc",
				"id":       fakeSnapID("pc"),
				"revision": snapRevisions["pc"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "pc-kernel",
				"id":       fakeSnapID("pc-kernel"),
				"revision": snapRevisions["pc-kernel"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "core20",
				"id":       fakeSnapID("core20"),
				"revision": snapRevisions["core20"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "snapd",
				"id":       fakeSnapID("snapd"),
				"revision": snapRevisions["snapd"].String(),
				"presence": "required",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	vset := vsetAssert.(*asserts.ValidationSet)

	devicestate.MockSnapstateDownload(func(
		ctx context.Context, st *state.State, name string, components []string, blobDirectory string, revOpts snapstate.RevisionOptions, opts snapstate.Options) (*state.TaskSet, *snap.Info, error,
	) {
		expectedRev, ok := snapRevisions[name]
		if !ok {
			return nil, nil, fmt.Errorf("unexpected snap name %q", name)
		}

		c.Check(revOpts.Revision.Unset(), Equals, true)

		tDownload := s.state.NewTask("fake-download", fmt.Sprintf("Download %s to track %s", name, revOpts.Channel))
		si := &snap.SideInfo{
			RealName: name,
			Revision: expectedRev,
			SnapID:   fakeSnapID(name),
		}

		snapsup := &snapstate.SnapSetup{
			SideInfo: si,
			Base:     "core20",
			Type:     snapTypes[name],
		}

		yaml := fmt.Sprintf(`name: %s
version: 1.0
epoch: 1
base: core20
`, name)

		if name == "pc" {
			snapsup.Base = "core22"
			yaml = fmt.Sprintf(`name: %s
version: 1.0
epoch: 1
base: core22
plugs:
  prereq-content:
    content: prereq-content
    interface: content
    default-provider: snap-1
    target: $SNAP/data-dir/target
`, name)
		}

		tDownload.Set("snap-setup", snapsup)

		_, info := snaptest.MakeTestSnapInfoWithFiles(c, yaml, nil, si)
		opts.PrereqTracker.Add(info)

		tValidate := s.state.NewTask("fake-validate", fmt.Sprintf("Validate %s", name))
		tValidate.Set("snap-setup-task", tDownload.ID())

		tValidate.WaitFor(tDownload)
		ts := state.NewTaskSet(tDownload, tValidate)
		ts.MarkEdge(tDownload, snapstate.SnapSetupEdge)
		ts.MarkEdge(tValidate, snapstate.LastBeforeLocalModificationsEdge)
		return ts, info, nil
	})

	s.state.Lock()
	defer s.state.Unlock()

	s.state.Set("refresh-privacy-key", "some-privacy-key")
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	_, err = devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		ValidationSets: []*asserts.ValidationSet{vset},
	})

	msg := `cannot create recovery system from model that is not self-contained:
  - cannot use snap "pc": base "core22" is missing
  - cannot use snap "pc": default provider "snap-1" or any alternative provider for content "prereq-content" is missing`

	c.Assert(err, ErrorMatches, msg)
}

func (s *deviceMgrSystemsCreateSuite) TestDeviceManagerCreateRecoverySystemValidationSetsMissingPrereqsOffline(c *C) {
	devicestate.SetBootOkRan(s.mgr, true)

	s.state.Lock()
	defer s.state.Unlock()

	snapRevisions := map[string]snap.Revision{
		"pc":        snap.R(10),
		"pc-kernel": snap.R(11),
		"core20":    snap.R(12),
		"snapd":     snap.R(13),
	}

	vsetAssert, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc",
				"id":       fakeSnapID("pc"),
				"revision": snapRevisions["pc"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "pc-kernel",
				"id":       fakeSnapID("pc-kernel"),
				"revision": snapRevisions["pc-kernel"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "core20",
				"id":       fakeSnapID("core20"),
				"revision": snapRevisions["core20"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "snapd",
				"id":       fakeSnapID("snapd"),
				"revision": snapRevisions["snapd"].String(),
				"presence": "required",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	vset := vsetAssert.(*asserts.ValidationSet)

	localSnaps := make([]snapstate.PathSnap, 0, len(snapRevisions))
	for name, rev := range snapRevisions {
		si := &snap.SideInfo{RealName: name, Revision: snap.R(rev.N), SnapID: fakeSnapID(name)}

		yaml := fmt.Sprintf(`name: %s
version: 1.0
epoch: 1
base: core20
`, name)

		if name == "pc" {
			yaml = fmt.Sprintf(`name: %s
version: 1.0
epoch: 1
base: core22
plugs:
  prereq-content:
    content: prereq-content
    interface: content
    default-provider: snap-1
    target: $SNAP/data-dir/target
`, name)
		}

		path := snaptest.MakeTestSnapWithFiles(c, yaml, [][]string(nil))

		localSnaps = append(localSnaps, snapstate.PathSnap{
			SideInfo: si,
			Path:     path,
		})

		s.setupSnapDeclForNameAndID(c, name, si.SnapID, "canonical")
		s.setupSnapRevisionForFileAndID(c, path, si.SnapID, "canonical", rev)
	}

	s.state.Set("refresh-privacy-key", "some-privacy-key")
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	_, err = devicestate.CreateRecoverySystem(s.state, "1234", devicestate.CreateRecoverySystemOptions{
		ValidationSets: []*asserts.ValidationSet{vset},
		LocalSnaps:     localSnaps,
		Offline:        true,
	})

	msg := `cannot create recovery system from model that is not self-contained:
  - cannot use snap "pc": base "core22" is missing
  - cannot use snap "pc": default provider "snap-1" or any alternative provider for content "prereq-content" is missing`

	c.Assert(err, ErrorMatches, msg)
}

func (s *deviceMgrSystemsCreateSuite) createSystemForRemoval(c *C, label string, expectedDownloads int, vSets []*asserts.ValidationSet, markDefault bool) {
	s.restartRequests = nil

	chg, err := devicestate.CreateRecoverySystem(s.state, label, devicestate.CreateRecoverySystemOptions{
		ValidationSets: vSets,
		TestSystem:     true,
		MarkDefault:    markDefault,
	})
	c.Assert(err, IsNil)
	c.Assert(chg, NotNil)
	tsks := chg.Tasks()

	c.Check(tsks, HasLen, (2*expectedDownloads)+2)

	tskCreate := tsks[0]
	tskFinalize := tsks[1]
	c.Assert(tskCreate.Summary(), Matches, fmt.Sprintf(`Create recovery system with label "%s"`, label))
	c.Check(tskFinalize.Summary(), Matches, fmt.Sprintf(`Finalize recovery system with label "%s"`, label))

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), IsNil)
	c.Assert(tskCreate.Status(), Equals, state.WaitStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoStatus)

	// a reboot is expected
	c.Check(s.restartRequests, DeepEquals, []restart.RestartType{restart.RestartSystemNow})

	validateCore20Seed(c, label, s.model, s.storeSigning.Trusted)
	m, err := s.bootloader.GetBootVars("try_recovery_system", "recovery_system_status")
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]string{
		"try_recovery_system":    label,
		"recovery_system_status": "try",
	})
	modeenvAfterCreate, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterCreate.CurrentRecoverySystems, testutil.Contains, label)
	c.Check(modeenvAfterCreate.GoodRecoverySystems, Not(testutil.Contains), label)

	restart.MockPending(s.state, restart.RestartUnset)
	s.state.Set("tried-systems", []string{label})
	s.bootloader.SetBootVars(map[string]string{
		"try_recovery_system":    "",
		"recovery_system_status": "",
	})
	s.bootloader.SetBootVarsCalls = 0

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	// simulate a restart and run change to completion
	s.mockRestartAndSettle(c, s.state, chg)

	c.Assert(chg.Err(), IsNil)
	c.Check(chg.IsReady(), Equals, true)
	c.Assert(tskCreate.Status(), Equals, state.DoneStatus)
	c.Assert(tskFinalize.Status(), Equals, state.DoneStatus)

	var triedSystemsAfterFinalize []string
	err = s.state.Get("tried-systems", &triedSystemsAfterFinalize)
	c.Assert(err, testutil.ErrorIs, state.ErrNoState)

	modeenvAfterFinalize, err := boot.ReadModeenv("")
	c.Assert(err, IsNil)
	c.Check(modeenvAfterFinalize.CurrentRecoverySystems, testutil.Contains, label)
	c.Check(modeenvAfterFinalize.GoodRecoverySystems, testutil.Contains, label)

	c.Check(s.bootloader.SetBootVarsCalls, Equals, 1)
	c.Check(filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", label, "snapd-new-file-log"), testutil.FileAbsent)

	if markDefault {
		var defaultSystem devicestate.DefaultRecoverySystem
		err := s.state.Get("default-recovery-system", &defaultSystem)
		c.Assert(err, IsNil)

		c.Assert(defaultSystem.System, Equals, label)
		c.Assert(defaultSystem.Model, Equals, s.model.Model())
		c.Assert(defaultSystem.BrandID, Equals, s.model.BrandID())
	}

	// boot.InitramfsUbuntuSeedDir and dirs.SnapSeedDir are usually different
	// mount points of the same device. to emulate this, we can copy the files
	// from boot.InitramfsUbuntuSeedDir (where they are written during creation)
	// to dirs.SnapSeedDir
	makeDirIdentical(c, boot.InitramfsUbuntuSeedDir, dirs.SnapSeedDir)
}

func makeDirIdentical(c *C, src, dest string) {
	srcCommonPaths := make(map[string]bool)
	// copy all files and make all dirs from src in dest
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		commonPath := strings.TrimPrefix(path, src)

		srcCommonPaths[commonPath] = true

		destName := filepath.Join(dest, commonPath)

		if destName == dest {
			return nil
		}

		if info.IsDir() {
			return os.MkdirAll(destName, info.Mode().Perm())
		}

		return osutil.CopyFile(path, destName, osutil.CopyFlagOverwrite)
	})
	c.Assert(err, IsNil)

	// remove all files and dirs from dest that are not in src
	err = filepath.WalkDir(dest, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		commonPath := strings.TrimPrefix(path, dest)

		if !srcCommonPaths[commonPath] {
			return os.RemoveAll(path)
		}

		return nil
	})
	c.Assert(err, IsNil)
}

func verifySystemRemoved(c *C, label string, expectedSnaps ...string) {
	systemDir := filepath.Join(boot.InitramfsUbuntuSeedDir, "systems", label)
	exists, _, err := osutil.DirExists(systemDir)
	c.Assert(err, IsNil)
	if exists {
		c.Errorf("system %q still exists", label)
		return
	}

	snapsDir := filepath.Join(boot.InitramfsUbuntuSeedDir, "snaps")
	entries, err := os.ReadDir(snapsDir)
	c.Assert(err, IsNil)

	foundSnaps := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		foundSnaps = append(foundSnaps, entry.Name())
	}

	c.Check(foundSnaps, testutil.DeepUnsortedMatches, expectedSnaps)
}

func (s *deviceMgrSystemsCreateSuite) TestRemoveRecoverySystemMockedRetry(c *C) {
	const mockRetry = true
	s.testRemoveRecoverySystem(c, mockRetry)
}

func (s *deviceMgrSystemsCreateSuite) TestRemoveRecoverySystem(c *C) {
	const mockRetry = false
	s.testRemoveRecoverySystem(c, mockRetry)
}

func (s *deviceMgrSystemsCreateSuite) testRemoveRecoverySystem(c *C, mockRetry bool) {
	restore := seed.MockTrusted(s.storeSigning.Trusted)
	s.AddCleanup(restore)

	s.state.Lock()
	defer s.state.Unlock()

	devicestate.SetBootOkRan(s.mgr, true)
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	// create a system that will use already installed snaps
	const markDefault = false
	const keepLabel = "keep"
	s.createSystemForRemoval(c, keepLabel, 0, nil, markDefault)

	snapRevisions := map[string]snap.Revision{
		"pc":        snap.R(1),  // this snap will be shared between validation sets
		"pc-kernel": snap.R(11), // remaining snaps are unique to the second recovery system
		"core20":    snap.R(12),
		"snapd":     snap.R(13),
	}

	for name, rev := range snapRevisions {
		// don't recreate this one
		if name == "pc" {
			continue
		}

		// add an extra file in there so that the snap has a new hash
		s.makeSnapInState(c, name, rev, [][]string{{"random-file", "random-content"}}, nil)
	}

	vsetAssert, err := s.brands.Signing("canonical").Sign(asserts.ValidationSetType, map[string]any{
		"type":         "validation-set",
		"authority-id": "canonical",
		"series":       "16",
		"account-id":   "canonical",
		"name":         "vset-1",
		"sequence":     "1",
		"snaps": []any{
			map[string]any{
				"name":     "pc",
				"id":       fakeSnapID("pc"),
				"revision": snapRevisions["pc"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "pc-kernel",
				"id":       fakeSnapID("pc-kernel"),
				"revision": snapRevisions["pc-kernel"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "core20",
				"id":       fakeSnapID("core20"),
				"revision": snapRevisions["core20"].String(),
				"presence": "required",
			},
			map[string]any{
				"name":     "snapd",
				"id":       fakeSnapID("snapd"),
				"revision": snapRevisions["snapd"].String(),
				"presence": "required",
			},
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}, nil, "")
	c.Assert(err, IsNil)

	const removeLabel = "remove"
	s.createSystemForRemoval(c, removeLabel, 0, []*asserts.ValidationSet{vsetAssert.(*asserts.ValidationSet)}, markDefault)

	chg, err := devicestate.RemoveRecoverySystem(s.state, removeLabel)
	c.Assert(err, IsNil)

	if mockRetry {
		tasks := chg.Tasks()
		if len(tasks) != 1 {
			c.Fatalf("expected 1 task, got %d", len(tasks))
		}

		// remove the recovery system to make sure we're testing the case where
		// we inspect the task for a list of snaps to remove, since inspecting
		// the seed would be impossible
		err := os.RemoveAll(filepath.Join(dirs.SnapSeedDir, "systems", removeLabel))
		c.Assert(err, IsNil)

		tasks[0].Set("snaps-to-remove", devicestate.UniqueSnapsInRecoverySystem{
			SnapPaths: []string{
				filepath.Join(dirs.SnapSeedDir, "snaps/pc-kernel_11.snap"),
				filepath.Join(dirs.SnapSeedDir, "snaps/core20_12.snap"),
				filepath.Join(dirs.SnapSeedDir, "snaps/snapd_13.snap"),
			},
		})
	}

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Check(chg.Err(), IsNil)
	c.Check(chg.Status(), Equals, state.DoneStatus)

	// these snaps are left over from the first recovery system
	remainingSnaps := []string{"pc_1.snap", "pc-kernel_2.snap", "core20_3.snap", "snapd_4.snap"}
	verifySystemRemoved(c, removeLabel, remainingSnaps...)
}

func (s *deviceMgrSystemsCreateSuite) TestRemoveRecoverySystemCurrentFailure(c *C) {
	restore := seed.MockTrusted(s.storeSigning.Trusted)
	s.AddCleanup(restore)

	s.state.Lock()
	defer s.state.Unlock()

	devicestate.SetBootOkRan(s.mgr, true)
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	const keep = "keep"
	const markDefault = false
	s.createSystemForRemoval(c, keep, 0, nil, markDefault)

	const label = "current"
	s.createSystemForRemoval(c, label, 0, nil, markDefault)

	// make it look like the most recently seeded system, we prevent the removal
	// of this
	s.state.Set("seeded-systems", []devicestate.SeededSystem{
		{
			System:  "current",
			Model:   "pc-20",
			BrandID: "canonical",
		},
	})

	chg, err := devicestate.RemoveRecoverySystem(s.state, label)
	c.Check(err, IsNil)

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), ErrorMatches, `(?s)cannot perform the following tasks.* \(cannot remove current recovery system: "current"\)`)
	c.Check(chg.Status(), Equals, state.ErrorStatus)
}

func (s *deviceMgrSystemsCreateSuite) TestRemoveRecoverySystemDefaultFailure(c *C) {
	restore := seed.MockTrusted(s.storeSigning.Trusted)
	s.AddCleanup(restore)

	s.state.Lock()
	defer s.state.Unlock()

	devicestate.SetBootOkRan(s.mgr, true)
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	const keep = "keep"
	const markDefault = true
	s.createSystemForRemoval(c, keep, 0, nil, markDefault)

	const label = "default"
	s.createSystemForRemoval(c, label, 0, nil, markDefault)

	chg, err := devicestate.RemoveRecoverySystem(s.state, label)
	c.Check(err, IsNil)

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), ErrorMatches, `(?s)cannot perform the following tasks.* \(cannot remove default recovery system: "default"\)`)
	c.Check(chg.Status(), Equals, state.ErrorStatus)
}

func (s *deviceMgrSystemsCreateSuite) TestRemoveRecoverySystemLastSystemFailure(c *C) {
	restore := seed.MockTrusted(s.storeSigning.Trusted)
	s.AddCleanup(restore)

	s.state.Lock()
	defer s.state.Unlock()

	devicestate.SetBootOkRan(s.mgr, true)
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	const label = "last"
	const markDefault = false
	s.createSystemForRemoval(c, label, 0, nil, markDefault)

	chg, err := devicestate.RemoveRecoverySystem(s.state, label)
	c.Check(err, IsNil)

	s.state.Unlock()
	s.settle(c)
	s.state.Lock()

	c.Assert(chg.Err(), ErrorMatches, `(?s)cannot perform the following tasks.* \(cannot remove last recovery system: "last"\)`)
	c.Check(chg.Status(), Equals, state.ErrorStatus)
}

func (s *deviceMgrSystemsCreateSuite) TestRemoveRecoverySystemNoSystemWithName(c *C) {
	restore := seed.MockTrusted(s.storeSigning.Trusted)
	s.AddCleanup(restore)

	s.state.Lock()
	defer s.state.Unlock()

	devicestate.SetBootOkRan(s.mgr, true)
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	const label = "last"
	const markDefault = false
	s.createSystemForRemoval(c, label, 0, nil, markDefault)

	const missing = "missing"
	_, err := devicestate.RemoveRecoverySystem(s.state, missing)
	c.Check(err, NotNil)
	c.Check(err, testutil.ErrorIs, devicestate.ErrNoRecoverySystem)
}

func (s *deviceMgrSystemsCreateSuite) waitfor(chg *state.Change) {
	s.state.Unlock()
	for i := 0; i < 5; i++ {
		s.se.Ensure()
		s.se.Wait()
		s.state.Lock()
		if chg.Status().Ready() {
			return
		}
		s.state.Unlock()
	}
	s.state.Lock()
}

func (s *deviceMgrSystemsCreateSuite) TestRemoveRecoverySystemConflict(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	devicestate.SetBootOkRan(s.mgr, true)
	s.mockStandardSnapsModeenvAndBootloaderState(c)

	for _, chgType := range []string{"create-recovery-system", "remove-recovery-system", "remodel"} {
		conflict := s.state.NewChange(chgType, "...")
		conflict.AddTask(s.state.NewTask(chgType, "..."))

		_, err := devicestate.RemoveRecoverySystem(s.state, "label")
		conflictErr, ok := err.(*snapstate.ChangeConflictError)
		c.Assert(ok, Equals, true, Commentf("expected a snapstate.ChangeConflictError, got %T", err))

		c.Check(conflictErr.ChangeID, Equals, conflict.ID())
		c.Check(conflictErr.ChangeKind, Equals, conflict.Kind())

		conflict.Abort()
		s.waitfor(conflict)
	}
}
