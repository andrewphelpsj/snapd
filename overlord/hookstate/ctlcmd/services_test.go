// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2017 Canonical Ltd
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

package ctlcmd_test

import (
	"context"
	"fmt"
	"sort"
	"strings"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/snapasserts"
	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/client/clientutil"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/osutil/user"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/overlord/hookstate"
	"github.com/snapcore/snapd/overlord/hookstate/ctlcmd"
	"github.com/snapcore/snapd/overlord/hookstate/hooktest"
	"github.com/snapcore/snapd/overlord/ifacestate/ifacerepo"
	"github.com/snapcore/snapd/overlord/servicestate"
	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/snapstate/snapstatetest"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/snaptest"
	"github.com/snapcore/snapd/store"
	"github.com/snapcore/snapd/store/storetest"
	"github.com/snapcore/snapd/systemd"
	"github.com/snapcore/snapd/testutil"
)

type fakeStore struct {
	storetest.Store
}

func (f *fakeStore) SnapAction(_ context.Context, currentSnaps []*store.CurrentSnap, actions []*store.SnapAction, assertQuery store.AssertionQuery, user *auth.UserState, opts *store.RefreshOptions) ([]store.SnapActionResult, []store.AssertionResult, error) {
	if assertQuery != nil {
		panic("no assertion query support")
	}
	if actions[0].Action == "install" {
		installs := make([]store.SnapActionResult, 0, len(actions))
		for _, a := range actions {
			snapName, instanceKey := snap.SplitInstanceName(a.InstanceName)
			if instanceKey != "" {
				panic(fmt.Sprintf("unexpected instance name %q in snap install action", a.InstanceName))
			}

			installs = append(installs, store.SnapActionResult{Info: &snap.Info{
				DownloadInfo: snap.DownloadInfo{
					Size: 1,
				},
				SideInfo: snap.SideInfo{
					RealName: snapName,
					Revision: snap.R(2),
				},
				Architectures: []string{"all"},
			}})
		}

		return installs, nil, nil
	}

	snaps := []store.SnapActionResult{{Info: &snap.Info{
		SideInfo: snap.SideInfo{
			RealName: "test-snap",
			Revision: snap.R(2),
			SnapID:   "test-snap-id",
		},
		Architectures: []string{"all"},
	}}, {Info: &snap.Info{
		SideInfo: snap.SideInfo{
			RealName: "other-snap",
			Revision: snap.R(2),
			SnapID:   "other-snap-id",
		},
		Architectures: []string{"all"},
	}}}
	return snaps, nil, nil
}

type appsSuiteDecoratorResult struct {
	daemonType string
	active     bool
	enabled    bool
}

type servicectlSuite struct {
	testutil.BaseTest
	st               *state.State
	fakeStore        fakeStore
	mockContext      *hookstate.Context
	mockHandler      *hooktest.MockHandler
	decoratorResults map[string]appsSuiteDecoratorResult
}

var _ = Suite(&servicectlSuite{})

const testSnapYaml = `name: test-snap
version: 1.0
summary: test-snap
apps:
 normal-app:
  command: bin/test
 test-service:
  command: bin/service
  daemon: simple
  reload-command: bin/reload
 another-service:
  command: bin/service
  daemon: simple
  reload-command: bin/reload
 user-service:
  command: bin/user-service
  daemon: simple
  daemon-scope: user
`

const otherSnapYaml = `name: other-snap
version: 1.0
summary: other-snap
apps:
 test-service:
  command: bin/service
  daemon: simple
  reload-command: bin/reload
`

func mockServiceChangeFunc(testServiceControlInputs func(appInfos []*snap.AppInfo, inst *servicestate.Instruction)) func() {
	return ctlcmd.MockServicestateControlFunc(func(st *state.State, appInfos []*snap.AppInfo, inst *servicestate.Instruction, cu *user.User, flags *servicestate.Flags, context *hookstate.Context) ([]*state.TaskSet, error) {
		testServiceControlInputs(appInfos, inst)
		return nil, fmt.Errorf("forced error")
	})
}

func (s *servicectlSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	oldRoot := dirs.GlobalRootDir
	dirs.SetRootDir(c.MkDir())

	testutil.MockCommand(c, "systemctl", "")

	s.BaseTest.AddCleanup(func() {
		dirs.SetRootDir(oldRoot)
	})
	s.BaseTest.AddCleanup(snap.MockSanitizePlugsSlots(func(snapInfo *snap.Info) {}))

	s.mockHandler = hooktest.NewMockHandler()

	s.st = state.New(nil)
	s.st.Lock()
	defer s.st.Unlock()

	repo := interfaces.NewRepository()
	ifacerepo.Replace(s.st, repo)

	snapstate.ReplaceStore(s.st, &s.fakeStore)

	// mock installed snaps
	info1 := snaptest.MockSnapCurrent(c, string(testSnapYaml), &snap.SideInfo{
		Revision: snap.R(1),
	})
	info2 := snaptest.MockSnapCurrent(c, string(otherSnapYaml), &snap.SideInfo{
		Revision: snap.R(1),
	})
	snapstate.Set(s.st, info1.InstanceName(), &snapstate.SnapState{
		Active: true,
		Sequence: snapstatetest.NewSequenceFromSnapSideInfos([]*snap.SideInfo{
			{
				RealName: info1.SnapName(),
				Revision: info1.Revision,
				SnapID:   "test-snap-id",
			},
		}),
		Current: info1.Revision,
	})
	snapstate.Set(s.st, info2.InstanceName(), &snapstate.SnapState{
		Active: true,
		Sequence: snapstatetest.NewSequenceFromSnapSideInfos([]*snap.SideInfo{
			{
				RealName: info2.SnapName(),
				Revision: info2.Revision,
				SnapID:   "other-snap-id",
			},
		}),
		Current: info2.Revision,
	})

	task := s.st.NewTask("test-task", "my test task")
	setup := &hookstate.HookSetup{Snap: "test-snap", Revision: snap.R(1), Hook: "test-hook"}

	var err error
	s.mockContext, err = hookstate.NewContext(task, task.State(), setup, s.mockHandler, "")
	c.Assert(err, IsNil)

	s.st.Set("seeded", true)
	s.st.Set("refresh-privacy-key", "privacy-key")
	s.AddCleanup(snapstatetest.UseFallbackDeviceModel())

	old := snapstate.EnforcedValidationSets
	s.AddCleanup(func() {
		snapstate.EnforcedValidationSets = old
	})
	snapstate.EnforcedValidationSets = func(st *state.State, extraVss ...*asserts.ValidationSet) (*snapasserts.ValidationSets, error) {
		return snapasserts.NewValidationSets(), nil
	}
}

func (s *servicectlSuite) TestStopCommand(c *C) {
	var serviceChangeFuncCalled bool
	restore := mockServiceChangeFunc(func(appInfos []*snap.AppInfo, inst *servicestate.Instruction) {
		serviceChangeFuncCalled = true
		c.Assert(appInfos, HasLen, 1)
		c.Assert(appInfos[0].Name, Equals, "test-service")
		c.Assert(inst, DeepEquals, &servicestate.Instruction{
			Action: "stop",
			Names:  []string{"test-snap.test-service"},
			StopOptions: client.StopOptions{
				Disable: false,
			},
			Users: client.UserSelector{
				Selector: client.UserSelectionList,
				Names:    []string{},
			},
		},
		)
	})
	defer restore()
	_, _, err := ctlcmd.Run(s.mockContext, []string{"stop", "test-snap.test-service"}, 0)
	c.Assert(err, NotNil)
	c.Check(err, ErrorMatches, "forced error")
	c.Assert(serviceChangeFuncCalled, Equals, true)
}

func (s *servicectlSuite) TestStopCommandUnknownService(c *C) {
	var serviceChangeFuncCalled bool
	restore := mockServiceChangeFunc(func(appInfos []*snap.AppInfo, inst *servicestate.Instruction) {
		serviceChangeFuncCalled = true
	})
	defer restore()
	_, _, err := ctlcmd.Run(s.mockContext, []string{"stop", "test-snap.fooservice"}, 0)
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, `unknown service: "test-snap.fooservice"`)
	c.Assert(serviceChangeFuncCalled, Equals, false)
}

func (s *servicectlSuite) TestStopCommandFailsOnOtherSnap(c *C) {
	var serviceChangeFuncCalled bool
	restore := mockServiceChangeFunc(func(appInfos []*snap.AppInfo, inst *servicestate.Instruction) {
		serviceChangeFuncCalled = true
	})
	defer restore()
	// verify that snapctl is not allowed to control services of other snaps (only the one of its hook)
	_, _, err := ctlcmd.Run(s.mockContext, []string{"stop", "other-snap.test-service"}, 0)
	c.Check(err, NotNil)
	c.Assert(err, ErrorMatches, `unknown service: "other-snap.test-service"`)
	c.Assert(serviceChangeFuncCalled, Equals, false)
}

func (s *servicectlSuite) TestStartCommand(c *C) {
	var serviceChangeFuncCalled bool
	restore := mockServiceChangeFunc(func(appInfos []*snap.AppInfo, inst *servicestate.Instruction) {
		serviceChangeFuncCalled = true
		c.Assert(appInfos, HasLen, 1)
		c.Assert(appInfos[0].Name, Equals, "test-service")
		c.Assert(inst, DeepEquals, &servicestate.Instruction{
			Action: "start",
			Names:  []string{"test-snap.test-service"},
			StartOptions: client.StartOptions{
				Enable: false,
			},
			Users: client.UserSelector{
				Selector: client.UserSelectionList,
				Names:    []string{},
			},
		},
		)
	})
	defer restore()
	_, _, err := ctlcmd.Run(s.mockContext, []string{"start", "test-snap.test-service"}, 0)
	c.Check(err, NotNil)
	c.Check(err, ErrorMatches, "forced error")
	c.Assert(serviceChangeFuncCalled, Equals, true)
}

func (s *servicectlSuite) TestRestartCommand(c *C) {
	var serviceChangeFuncCalled bool
	restore := mockServiceChangeFunc(func(appInfos []*snap.AppInfo, inst *servicestate.Instruction) {
		serviceChangeFuncCalled = true
		c.Assert(appInfos, HasLen, 1)
		c.Assert(appInfos[0].Name, Equals, "test-service")
		c.Assert(inst, DeepEquals, &servicestate.Instruction{
			Action: "restart",
			Names:  []string{"test-snap.test-service"},
			RestartOptions: client.RestartOptions{
				Reload: false,
			},
			Users: client.UserSelector{
				Selector: client.UserSelectionList,
				Names:    []string{},
			},
		},
		)
	})
	defer restore()
	_, _, err := ctlcmd.Run(s.mockContext, []string{"restart", "test-snap.test-service"}, 0)
	c.Check(err, NotNil)
	c.Check(err, ErrorMatches, "forced error")
	c.Assert(serviceChangeFuncCalled, Equals, true)
}

func (s *servicectlSuite) TestServiceCommandsScope(c *C) {
	checkInvocation := func(action string, names, args []string, expected *servicestate.Instruction, expectedErr string) {
		var serviceChangeFuncCalled bool
		restore := mockServiceChangeFunc(func(appInfos []*snap.AppInfo, inst *servicestate.Instruction) {
			serviceChangeFuncCalled = true
			c.Check(appInfos, HasLen, 1)
			c.Check(appInfos[0].Name, Equals, "test-service")
			c.Check(inst, DeepEquals, expected)
		})
		defer restore()
		_, _, err := ctlcmd.Run(s.mockContext, append([]string{action}, append(names, args...)...), 0)
		c.Check(err, NotNil)
		if expectedErr != "" {
			c.Check(err, ErrorMatches, expectedErr)
			c.Check(serviceChangeFuncCalled, Equals, false)
		} else {
			// bit weird we are always returning an error in the test code
			c.Check(err, ErrorMatches, "forced error")
			c.Check(serviceChangeFuncCalled, Equals, true)
		}
	}

	for _, c := range []string{"start", "stop", "restart"} {
		names := []string{"test-snap.test-service"}
		checkInvocation(c, names, []string{"--system"}, &servicestate.Instruction{
			Action: c,
			Names:  names,
			Scope:  []string{"system"},
			Users: client.UserSelector{
				Selector: client.UserSelectionList,
				Names:    []string{},
			},
		}, "")
		checkInvocation(c, names, []string{"--user"}, &servicestate.Instruction{
			Action: c,
			Names:  names,
			Scope:  []string{"user"},
			Users: client.UserSelector{
				Selector: client.UserSelectionSelf,
			},
		}, "")
		checkInvocation(c, names, []string{"--users=all"}, &servicestate.Instruction{
			Action: c,
			Names:  names,
			Scope:  []string{"user"},
			Users: client.UserSelector{
				Selector: client.UserSelectionAll,
			},
		}, "")

		// check combined cases
		checkInvocation(c, names, []string{"--system", "--users=all"}, &servicestate.Instruction{
			Action: c,
			Names:  names,
			Users: client.UserSelector{
				Selector: client.UserSelectionAll,
			},
		}, "")

		// we *must* provide a value for --users
		checkInvocation(c, names, []string{"--users"}, nil, "expected argument for flag `--users'")

		// that value must only be 'all'
		checkInvocation(c, names, []string{"--users=foo"}, nil, "only \"all\" is supported as a value for --users")

		// --system and --user not allowed together
		checkInvocation(c, names, []string{"--system", "--user"}, nil, "--system and --user cannot be used in conjunction with each other")

		// --user and --users not allowed together
		checkInvocation(c, names, []string{"--users=all", "--user"}, nil, "--user and --users cannot be used in conjunction with each other")
	}
}

func (s *servicectlSuite) TestConflictingChange(c *C) {
	s.st.Lock()
	task := s.st.NewTask("link-snap", "conflicting task")
	snapsup := snapstate.SnapSetup{
		SideInfo: &snap.SideInfo{
			RealName: "test-snap",
			SnapID:   "test-snap-id-1",
			Revision: snap.R(1),
		},
	}
	task.Set("snap-setup", snapsup)
	chg := s.st.NewChange("conflicting change", "install change")
	chg.AddTask(task)
	s.st.Unlock()

	_, _, err := ctlcmd.Run(s.mockContext, []string{"start", "test-snap.test-service"}, 0)
	c.Check(err, NotNil)
	c.Check(err, ErrorMatches, `snap "test-snap" has "conflicting change" change in progress`)
}

var (
	installTaskKinds = []string{
		"prerequisites",
		"download-snap",
		"validate-snap",
		"mount-snap",
		"copy-snap-data",
		"setup-profiles",
		"link-snap",
		"auto-connect",
		"set-auto-aliases",
		"setup-aliases",
		"run-hook[install]",
		"run-hook[default-configure]",
		"start-snap-services",
		"run-hook[configure]",
		"run-hook[check-health]",
	}

	refreshTaskKinds = []string{
		"prerequisites",
		"download-snap",
		"validate-snap",
		"mount-snap",
		"run-hook[pre-refresh]",
		"stop-snap-services",
		"remove-aliases",
		"unlink-current-snap",
		"copy-snap-data",
		"setup-profiles",
		"link-snap",
		"auto-connect",
		"set-auto-aliases",
		"setup-aliases",
		"run-hook[post-refresh]",
		"start-snap-services",
		"cleanup",
		"run-hook[configure]",
		"run-hook[check-health]",
	}
)

func (s *servicectlSuite) TestQueuedCommands(c *C) {
	s.st.Lock()

	chg := s.st.NewChange("install change", "install change")
	installed, tts, err := snapstate.InstallMany(s.st, []string{"one", "two"}, nil, 0, nil)
	c.Assert(err, IsNil)
	c.Check(installed, DeepEquals, []string{"one", "two"})
	c.Assert(tts, HasLen, 2)
	c.Assert(taskKinds(tts[0].Tasks()), DeepEquals, installTaskKinds)
	c.Assert(taskKinds(tts[1].Tasks()), DeepEquals, installTaskKinds)
	chg.AddAll(tts[0])
	chg.AddAll(tts[1])

	s.st.Unlock()

	for _, ts := range tts {
		tsTasks := ts.Tasks()
		// assumes configure task is last
		task := tsTasks[len(tsTasks)-1]
		c.Assert(task.Kind(), Equals, "run-hook")
		setup := &hookstate.HookSetup{Snap: "test-snap", Revision: snap.R(1), Hook: "configure"}
		context, err := hookstate.NewContext(task, task.State(), setup, s.mockHandler, "")
		c.Assert(err, IsNil)

		_, _, err = ctlcmd.Run(context, []string{"stop", "test-snap.test-service"}, 0)
		c.Check(err, IsNil)
		_, _, err = ctlcmd.Run(context, []string{"start", "test-snap.test-service"}, 0)
		c.Check(err, IsNil)
		_, _, err = ctlcmd.Run(context, []string{"restart", "test-snap.test-service"}, 0)
		c.Check(err, IsNil)
	}

	s.st.Lock()
	defer s.st.Unlock()

	expectedTaskKinds := append(installTaskKinds, "exec-command", "service-control", "exec-command", "service-control", "exec-command", "service-control")
	checkLaneTasks := func(lane int) {
		laneTasks := chg.LaneTasks(lane)
		c.Assert(taskKinds(laneTasks), DeepEquals, expectedTaskKinds)
		c.Check(laneTasks[13].Summary(), Matches, `Run configure hook of .* snap if present`)
		c.Check(laneTasks[15].Summary(), Equals, "stop of [test-snap.test-service]")
		c.Check(laneTasks[17].Summary(), Equals, "start of [test-snap.test-service]")
		c.Check(laneTasks[19].Summary(), Equals, "restart of [test-snap.test-service]")
	}
	checkLaneTasks(1)
	checkLaneTasks(2)
}

func (s *servicectlSuite) testQueuedCommandsOrdering(c *C, hook string, singleTransaction bool) {
	var transaction = client.TransactionPerSnap
	if singleTransaction {
		transaction = client.TransactionAllSnaps
	}

	s.st.Lock()

	chg := s.st.NewChange("install change", "install change")
	installed, tts, err := snapstate.InstallMany(s.st, []string{"one", "two"}, nil, 0, &snapstate.Flags{Transaction: transaction})
	c.Assert(err, IsNil)
	c.Check(installed, DeepEquals, []string{"one", "two"})
	c.Assert(tts, HasLen, 2)
	c.Assert(taskKinds(tts[0].Tasks()), DeepEquals, installTaskKinds)
	c.Assert(taskKinds(tts[1].Tasks()), DeepEquals, installTaskKinds)
	chg.AddAll(tts[0])
	chg.AddAll(tts[1])

	// Mock snaps as installed for the ctlcmd.Run calls below
	for _, snapName := range installed {
		var testSnapYaml = `name: %s
version: 1.0
apps:
 test-service:
  command: bin/service
  daemon: simple
`
		info := snaptest.MockSnapCurrent(c, fmt.Sprintf(testSnapYaml, snapName), &snap.SideInfo{
			Revision: snap.R(1),
		})
		snapstate.Set(s.st, info.InstanceName(), &snapstate.SnapState{
			Active: true,
			Sequence: snapstatetest.NewSequenceFromSnapSideInfos([]*snap.SideInfo{
				{
					RealName: info.SnapName(),
					Revision: info.Revision,
					SnapID:   snapName + "-id",
				},
			}),
			Current: info.Revision,
		})
	}

	s.st.Unlock()

	hookTasks := make([]*state.Task, 2)
	for i, ts := range tts {
		tsTasks := ts.Tasks()
		switch hook {
		case "default-configure":
			// default-configure hook task is the 4th to last task (check installTaskKinds)
			hookTasks[i] = tsTasks[len(tsTasks)-4]
		case "configure":
			// configure hook is 2nd to last task (check installTaskKinds)
			hookTasks[i] = tsTasks[len(tsTasks)-2]
		default:
			c.Errorf("unexpected hook %q", hook)
		}
		c.Assert(hookTasks[i].Kind(), Equals, "run-hook")

		s.st.Lock()
		var setup *hookstate.HookSetup
		c.Assert(hookTasks[i].Get("hook-setup", &setup), IsNil)
		s.st.Unlock()

		c.Assert(setup.Hook, Equals, hook)

		// reuse existing services
		setup = &hookstate.HookSetup{Snap: installed[i], Revision: snap.R(1), Hook: hook}
		context, err := hookstate.NewContext(hookTasks[i], hookTasks[i].State(), setup, s.mockHandler, "")
		c.Assert(err, IsNil)

		// simulate running service commands inside the default-configure hook
		_, _, err = ctlcmd.Run(context, []string{"stop", fmt.Sprintf("%s.test-service", installed[i])}, 0)
		c.Assert(err, IsNil)
		_, _, err = ctlcmd.Run(context, []string{"start", fmt.Sprintf("%s.test-service", installed[i])}, 0)
		c.Assert(err, IsNil)
	}

	s.st.Lock()
	defer s.st.Unlock()

	cmdTasksPerSnap := make(map[string][]*state.Task, 2)
	for _, t := range chg.Tasks() {
		if t.Kind() != "exec-command" && t.Kind() != "service-control" {
			continue
		}
		var snapName string
		if strings.Contains(t.Summary(), "one") {
			snapName = "one"
		} else if strings.Contains(t.Summary(), "two") {
			snapName = "two"
		} else {
			c.Errorf("unexpected task summary: %q", t.Summary())
		}
		cmdTasksPerSnap[snapName] = append(cmdTasksPerSnap[snapName], t)
	}
	c.Assert(cmdTasksPerSnap, HasLen, 2)

	// check command tasks for snap "one"
	c.Assert(taskKinds(cmdTasksPerSnap["one"]), DeepEquals, []string{"exec-command", "service-control", "exec-command", "service-control"})
	c.Check(cmdTasksPerSnap["one"][0].Summary(), Equals, "stop of [one.test-service]")
	c.Check(cmdTasksPerSnap["one"][2].Summary(), Equals, "start of [one.test-service]")
	// check command tasks for snap "two"
	c.Assert(taskKinds(cmdTasksPerSnap["two"]), DeepEquals, []string{"exec-command", "service-control", "exec-command", "service-control"})
	c.Check(cmdTasksPerSnap["two"][0].Summary(), Equals, "stop of [two.test-service]")
	c.Check(cmdTasksPerSnap["two"][2].Summary(), Equals, "start of [two.test-service]")

	var expectedHaltTaskKinds, expectedWaitTaskKinds []string
	switch hook {
	case "default-configure":
		// service command tasks are injected after start-snap-services
		expectedWaitTaskKinds = []string{"start-snap-services"}
		expectedHaltTaskKinds = []string{"run-hook[configure]", "run-hook[check-health]"}
	case "configure":
		// service command tasks are queued after all tasks
		expectedWaitTaskKinds = installTaskKinds
		expectedHaltTaskKinds = []string{}
	}

	var snapNameFromTask = func(t *state.Task) string {
		if t.Kind() == "run-hook" {
			var setup *hookstate.HookSetup
			c.Assert(t.Get("hook-setup", &setup), IsNil)
			return setup.Snap
		}
		setup, err := snapstate.TaskSnapSetup(t)
		c.Assert(err, IsNil)
		return setup.InstanceName()
	}

	for snapName, cmdTasks := range cmdTasksPerSnap {
		for _, t := range cmdTasks {
			var filteredHaltTasks, filteredWaitTasks []*state.Task
			for _, wt := range t.WaitTasks() {
				// filter out command tasks
				if wt.Kind() == "exec-command" || wt.Kind() == "service-control" {
					continue
				}
				// Check task is for the correct snap
				c.Assert(snapNameFromTask(wt), Equals, snapName)
				filteredWaitTasks = append(filteredWaitTasks, wt)
			}
			for _, ht := range t.HaltTasks() {
				// filter out command tasks
				if ht.Kind() == "exec-command" || ht.Kind() == "service-control" {
					continue
				}
				// Check task is for the correct snap
				c.Assert(snapNameFromTask(ht), Equals, snapName)
				filteredHaltTasks = append(filteredHaltTasks, ht)
			}
			c.Assert(taskKinds(filteredWaitTasks), DeepEquals, expectedWaitTaskKinds)
			c.Assert(taskKinds(filteredHaltTasks), DeepEquals, expectedHaltTaskKinds)
		}
	}
}

func (s *servicectlSuite) TestQueuedCommandsOrderingDefaultConfigureHook(c *C) {
	const hook = "default-configure"
	const singleTransaction = false
	s.testQueuedCommandsOrdering(c, hook, singleTransaction)
}

func (s *servicectlSuite) TestQueuedCommandsOrderingDefaultConfigureHookSingleTransaction(c *C) {
	const hook = "default-configure"
	const singleTransaction = true
	s.testQueuedCommandsOrdering(c, hook, singleTransaction)
}

func (s *servicectlSuite) TestQueuedCommandsOrderingConfigureHook(c *C) {
	const hook = "configure"
	const singleTransaction = false
	s.testQueuedCommandsOrdering(c, hook, singleTransaction)
}

// NOTE: It is tricky to get snap name for all task kinds in the case of configure hook
// so this test is left commented out just for clarity, but it will fail.
// This is a non-issue for configure hook since the command tasks are queued at the very
// end of the change unlike the default-configure hook.
//
// func (s *servicectlSuite) TestQueuedCommandsOrderingConfigureHookSingleTransaction(c *C) {
// 	const hook = "configure"
// 	const singleTransaction = true
// 	s.testQueuedCommandsOrdering(c, hook, singleTransaction)
// }

func (s *servicectlSuite) testQueueCommandsConfigureHookFinalTask(c *C, changeKind, finalTaskKind string) {
	s.st.Lock()

	chg := s.st.NewChange(changeKind, "seeding change")
	finalTask := s.st.NewTask(finalTaskKind, "")
	chg.AddTask(finalTask)
	configure := s.st.NewTask("run-hook", "")
	chg.AddTask(configure)

	s.st.Unlock()

	setup := &hookstate.HookSetup{Snap: "test-snap", Revision: snap.R(1), Hook: "configure"}
	context, err := hookstate.NewContext(configure, configure.State(), setup, s.mockHandler, "")
	c.Assert(err, IsNil)

	_, _, err = ctlcmd.Run(context, []string{"stop", "test-snap.test-service"}, 0)
	c.Check(err, IsNil)
	_, _, err = ctlcmd.Run(context, []string{"start", "test-snap.test-service"}, 0)
	c.Check(err, IsNil)

	s.st.Lock()
	defer s.st.Unlock()

	var finalWaitTasks []string
	for _, t := range finalTask.WaitTasks() {
		taskInfo := fmt.Sprintf("%s:%s", t.Kind(), t.Summary())
		finalWaitTasks = append(finalWaitTasks, taskInfo)

		var wait []string
		var hasRunHook bool
		for _, wt := range t.WaitTasks() {
			if wt.Kind() != "run-hook" {
				taskInfo = fmt.Sprintf("%s:%s", wt.Kind(), wt.Summary())
				wait = append(wait, taskInfo)
			} else {
				hasRunHook = true
			}
		}
		c.Assert(hasRunHook, Equals, true)

		switch t.Kind() {
		case "exec-command":
			var argv []string
			c.Assert(t.Get("argv", &argv), IsNil)
			c.Check(argv, HasLen, 3)
			switch argv[1] {
			case "stop":
				c.Check(wait, HasLen, 0)
			case "start":
				c.Check(wait, DeepEquals, []string{
					`exec-command:stop of [test-snap.test-service]`,
					`service-control:Run service command "stop" for services ["test-service"] of snap "test-snap"`})
			default:
				c.Fatalf("unexpected command: %q", argv[1])
			}
		case "service-control":
			var sa servicestate.ServiceAction
			c.Assert(t.Get("service-action", &sa), IsNil)
			c.Check(sa.Services, DeepEquals, []string{"test-service"})
			switch sa.Action {
			case "stop":
				c.Check(wait, DeepEquals, []string{
					"exec-command:stop of [test-snap.test-service]"})
			case "start":
				c.Check(wait, DeepEquals, []string{
					"exec-command:start of [test-snap.test-service]",
					"exec-command:stop of [test-snap.test-service]",
					`service-control:Run service command "stop" for services ["test-service"] of snap "test-snap"`})
			}
		default:
			c.Fatalf("unexpected task: %s", t.Kind())
		}

	}
	c.Check(finalWaitTasks, DeepEquals, []string{
		`exec-command:stop of [test-snap.test-service]`,
		`service-control:Run service command "stop" for services ["test-service"] of snap "test-snap"`,
		`exec-command:start of [test-snap.test-service]`,
		`service-control:Run service command "start" for services ["test-service"] of snap "test-snap"`})
	c.Check(finalTask.HaltTasks(), HasLen, 0)
}

func (s *servicectlSuite) TestQueuedCommandsRunBeforeMarkSeeded(c *C) {
	s.testQueueCommandsConfigureHookFinalTask(c, "seed", "mark-seeded")
}

func (s *servicectlSuite) TestQueuedCommandsRunBeforeSetModel(c *C) {
	s.testQueueCommandsConfigureHookFinalTask(c, "remodel", "set-model")
}

func (s *servicectlSuite) TestQueuedCommandsUpdateMany(c *C) {
	oldAutoAliases := snapstate.AutoAliases
	snapstate.AutoAliases = func(*state.State, *snap.Info) (map[string]string, error) {
		return nil, nil
	}
	defer func() { snapstate.AutoAliases = oldAutoAliases }()

	s.st.Lock()

	chg := s.st.NewChange("update many change", "update change")
	installed, tts, err := snapstate.UpdateMany(context.Background(), s.st, []string{"test-snap", "other-snap"}, nil, 0, nil)
	c.Assert(err, IsNil)
	sort.Strings(installed)
	c.Check(installed, DeepEquals, []string{"other-snap", "test-snap"})
	c.Assert(tts, HasLen, 3)
	c.Assert(taskKinds(tts[0].Tasks()), DeepEquals, refreshTaskKinds)
	c.Assert(taskKinds(tts[1].Tasks()), DeepEquals, refreshTaskKinds)
	c.Assert(taskKinds(tts[2].Tasks()), DeepEquals, []string{"check-rerefresh"})
	c.Assert(tts[2].Tasks()[0].Kind(), Equals, "check-rerefresh")
	chg.AddAll(tts[0])
	chg.AddAll(tts[1])

	s.st.Unlock()

	for _, ts := range tts[:2] {
		tsTasks := ts.Tasks()
		// assumes configure task is last
		task := tsTasks[len(tsTasks)-1]
		c.Assert(task.Kind(), Equals, "run-hook")
		setup := &hookstate.HookSetup{Snap: "test-snap", Revision: snap.R(1), Hook: "configure"}
		context, err := hookstate.NewContext(task, task.State(), setup, s.mockHandler, "")
		c.Assert(err, IsNil)

		_, _, err = ctlcmd.Run(context, []string{"stop", "test-snap.test-service"}, 0)
		c.Check(err, IsNil)
		_, _, err = ctlcmd.Run(context, []string{"start", "test-snap.test-service"}, 0)
		c.Check(err, IsNil)
		_, _, err = ctlcmd.Run(context, []string{"restart", "test-snap.test-service"}, 0)
		c.Check(err, IsNil)
	}

	s.st.Lock()
	defer s.st.Unlock()

	expectedTaskKinds := append(refreshTaskKinds, "exec-command", "service-control", "exec-command", "service-control", "exec-command", "service-control")
	for i := 1; i <= 2; i++ {
		laneTasks := chg.LaneTasks(i)
		c.Assert(taskKinds(laneTasks), DeepEquals, expectedTaskKinds)
		c.Check(laneTasks[17].Summary(), Matches, `Run configure hook of .* snap if present`)
		c.Check(laneTasks[19].Summary(), Equals, "stop of [test-snap.test-service]")
		c.Check(laneTasks[20].Summary(), Equals, `Run service command "stop" for services ["test-service"] of snap "test-snap"`)
		c.Check(laneTasks[21].Summary(), Equals, "start of [test-snap.test-service]")
		c.Check(laneTasks[22].Summary(), Equals, `Run service command "start" for services ["test-service"] of snap "test-snap"`)
		c.Check(laneTasks[23].Summary(), Equals, "restart of [test-snap.test-service]")
		c.Check(laneTasks[24].Summary(), Equals, `Run service command "restart" for services ["test-service"] of snap "test-snap"`)
	}
}

func (s *servicectlSuite) TestQueuedCommandsSingleLane(c *C) {
	s.st.Lock()

	chg := s.st.NewChange("install change", "install change")
	ts, err := snapstate.Install(context.Background(), s.st, "one", &snapstate.RevisionOptions{Revision: snap.R(1)}, 0, snapstate.Flags{})
	c.Assert(err, IsNil)
	c.Assert(taskKinds(ts.Tasks()), DeepEquals, installTaskKinds)
	chg.AddAll(ts)

	s.st.Unlock()

	tsTasks := ts.Tasks()
	// assumes configure task is last
	task := tsTasks[len(tsTasks)-1]
	c.Assert(task.Kind(), Equals, "run-hook")
	setup := &hookstate.HookSetup{Snap: "test-snap", Revision: snap.R(1), Hook: "configure"}
	context, err := hookstate.NewContext(task, task.State(), setup, s.mockHandler, "")
	c.Assert(err, IsNil)

	_, _, err = ctlcmd.Run(context, []string{"stop", "test-snap.test-service"}, 0)
	c.Check(err, IsNil)
	_, _, err = ctlcmd.Run(context, []string{"start", "test-snap.test-service"}, 0)
	c.Check(err, IsNil)
	_, _, err = ctlcmd.Run(context, []string{"restart", "test-snap.test-service"}, 0)
	c.Check(err, IsNil)

	s.st.Lock()
	defer s.st.Unlock()

	laneTasks := chg.LaneTasks(0)
	c.Assert(taskKinds(laneTasks), DeepEquals, append(installTaskKinds, "exec-command", "service-control", "exec-command", "service-control", "exec-command", "service-control"))
	c.Check(laneTasks[13].Summary(), Matches, `Run configure hook of .* snap if present`)
	c.Check(laneTasks[15].Summary(), Equals, "stop of [test-snap.test-service]")
	c.Check(laneTasks[17].Summary(), Equals, "start of [test-snap.test-service]")
	c.Check(laneTasks[19].Summary(), Equals, "restart of [test-snap.test-service]")
}

func (s *servicectlSuite) TestTwoServices(c *C) {
	restore := systemd.MockSystemctl(func(args ...string) (buf []byte, err error) {
		switch args[0] {
		case "show":
			c.Check(args[2], Matches, `snap\.test-snap\.\w+-service\.service`)
			return []byte(fmt.Sprintf(`Id=%s
Names=%[1]s
Type=simple
ActiveState=active
UnitFileState=enabled
NeedDaemonReload=no
`, args[2])), nil
		case "--user":
			c.Check(args[1], Equals, "--global")
			c.Check(args[2], Equals, "is-enabled")
			return []byte("enabled\n"), nil
		default:
			c.Errorf("unexpected systemctl command: %v", args)
			return nil, fmt.Errorf("should not be reached")
		}
	})
	defer restore()

	stdout, stderr, err := ctlcmd.Run(s.mockContext, []string{"services"}, 0)
	c.Assert(err, IsNil)
	c.Check(string(stdout), Equals, `
Service                    Startup  Current  Notes
test-snap.another-service  enabled  active   -
test-snap.test-service     enabled  active   -
test-snap.user-service     enabled  -        user
`[1:])
	c.Check(string(stderr), Equals, "")
}

func (s *servicectlSuite) TestServices(c *C) {
	restore := systemd.MockSystemctl(func(args ...string) (buf []byte, err error) {
		c.Assert(args[0], Equals, "show")
		c.Check(args[2], Equals, "snap.test-snap.test-service.service")
		return []byte(`Id=snap.test-snap.test-service.service
Names=snap.test-snap.test-service.service
Type=simple
ActiveState=active
UnitFileState=enabled
NeedDaemonReload=no
`), nil
	})
	defer restore()

	stdout, stderr, err := ctlcmd.Run(s.mockContext, []string{"services", "test-snap.test-service"}, 0)
	c.Assert(err, IsNil)
	c.Check(string(stdout), Equals, `
Service                 Startup  Current  Notes
test-snap.test-service  enabled  active   -
`[1:])
	c.Check(string(stderr), Equals, "")
}

func (s *servicectlSuite) TestServicesAsUserWithGlobal(c *C) {
	restore := systemd.MockSystemctl(func(args ...string) (buf []byte, err error) {
		c.Assert(args[0], Equals, "show")
		c.Check(args[2], Equals, "snap.test-snap.test-service.service")
		return []byte(`Id=snap.test-snap.test-service.service
Names=snap.test-snap.test-service.service
Type=simple
ActiveState=active
UnitFileState=enabled
NeedDaemonReload=no
`), nil
	})
	defer restore()

	stdout, stderr, err := ctlcmd.Run(s.mockContext, []string{"services", "--global", "test-snap.test-service"}, 1337)
	c.Assert(err, IsNil)
	c.Check(string(stdout), Equals, `
Service                 Startup  Current  Notes
test-snap.test-service  enabled  active   -
`[1:])
	c.Check(string(stderr), Equals, "")
}

func (s *servicectlSuite) DecorateWithStatus(appInfo *client.AppInfo, snapApp *snap.AppInfo) error {
	name := snapApp.Snap.RealName + "." + appInfo.Name
	dec, ok := s.decoratorResults[name]
	if !ok {
		return fmt.Errorf("%s not found in expected test decorator results", name)
	}
	appInfo.Daemon = dec.daemonType
	appInfo.Enabled = dec.enabled
	appInfo.Active = dec.active
	return nil
}

func (s *servicectlSuite) TestServicesUserSwitch(c *C) {
	restore := ctlcmd.MockNewStatusDecorator(func(ctx context.Context, isGlobal bool, uid string) clientutil.StatusDecorator {
		c.Check(isGlobal, Equals, false)
		c.Check(uid, Equals, "0")
		return s
	})
	defer restore()

	s.decoratorResults = map[string]appsSuiteDecoratorResult{
		"test-snap.user-service": {
			daemonType: "simple",
			active:     true,
			enabled:    true,
		},
	}

	stdout, stderr, err := ctlcmd.Run(s.mockContext, []string{"services", "--user", "test-snap.user-service"}, 0)
	c.Assert(err, IsNil)
	c.Check(string(stdout), Equals, `
Service                 Startup  Current  Notes
test-snap.user-service  enabled  active   user
`[1:])
	c.Check(string(stderr), Equals, "")
}

func (s *servicectlSuite) TestServicesAsUser(c *C) {
	restore := ctlcmd.MockNewStatusDecorator(func(ctx context.Context, isGlobal bool, uid string) clientutil.StatusDecorator {
		c.Check(isGlobal, Equals, false)
		c.Check(uid, Equals, "1337")
		return s
	})
	defer restore()

	s.decoratorResults = map[string]appsSuiteDecoratorResult{
		"test-snap.user-service": {
			daemonType: "simple",
			active:     true,
			enabled:    true,
		},
	}

	stdout, stderr, err := ctlcmd.Run(s.mockContext, []string{"services", "test-snap.user-service"}, 1337)
	c.Assert(err, IsNil)
	c.Check(string(stdout), Equals, `
Service                 Startup  Current  Notes
test-snap.user-service  enabled  active   user
`[1:])
	c.Check(string(stderr), Equals, "")
}

func (s *servicectlSuite) TestAppStatusInvalidUserGlobalSwitches(c *C) {
	_, _, err := ctlcmd.Run(s.mockContext, []string{"services", "--global", "--user"}, 0)
	c.Assert(err, ErrorMatches, "cannot combine --global and --user switches.")
}

func (s *servicectlSuite) TestServicesWithoutContext(c *C) {
	actions := []string{
		"start",
		"stop",
		"restart",
	}

	for _, action := range actions {
		_, _, err := ctlcmd.Run(nil, []string{action, "foo"}, 0)
		expectedError := fmt.Sprintf(`cannot invoke snapctl operation commands \(here "%s"\) from outside of a snap`, action)
		c.Check(err, ErrorMatches, expectedError)
	}
}
