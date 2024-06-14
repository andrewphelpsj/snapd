package snapstate_test

import (
	"context"
	"fmt"

	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/snapstate/sequence"
	"github.com/snapcore/snapd/overlord/snapstate/snapstatetest"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snap/naming"
	"github.com/snapcore/snapd/snap/snaptest"
	"github.com/snapcore/snapd/store"
	. "gopkg.in/check.v1"
)

type TargetTestSuite struct {
	snapmgrBaseTest
}

var _ = Suite(&TargetTestSuite{})

func (s *TargetTestSuite) TestInstallWithComponents(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	const (
		snapName = "test-snap"
		compName = "test-component"
		channel  = "channel-for-components"
	)
	s.fakeStore.snapResourcesFn = func(info *snap.Info) []store.SnapResourceResult {
		c.Assert(info.SnapName(), DeepEquals, snapName)

		return []store.SnapResourceResult{
			{
				DownloadInfo: snap.DownloadInfo{
					DownloadURL: fmt.Sprintf("http://example.com/%s", snapName),
				},
				Name:      compName,
				Revision:  1,
				Type:      fmt.Sprintf("component/%s", snap.TestComponent),
				Version:   "1.0",
				CreatedAt: "2024-01-01T00:00:00Z",
			},
		}
	}

	goal := snapstate.StoreInstallGoal(snapstate.StoreSnap{
		InstanceName: snapName,
		Components:   []string{compName},
		RevOpts: snapstate.RevisionOptions{
			Channel: channel,
		},
	})

	info, ts, err := snapstate.InstallOne(context.Background(), s.state, goal, snapstate.Options{})
	c.Assert(err, IsNil)

	c.Check(info.InstanceName(), Equals, snapName)
	c.Check(info.Channel, Equals, channel)
	c.Check(info.Components[compName].Name, Equals, compName)

	verifyInstallTasksWithComponents(c, snap.TypeApp, 0, 0, []string{compName}, ts)
}

func (s *TargetTestSuite) TestInstallWithComponentsMissingResource(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	const (
		snapName = "test-snap"
		compName = "test-component"
		channel  = "channel-for-components"
	)
	s.fakeStore.snapResourcesFn = func(info *snap.Info) []store.SnapResourceResult {
		c.Assert(info.SnapName(), DeepEquals, snapName)

		return []store.SnapResourceResult{
			{
				DownloadInfo: snap.DownloadInfo{
					DownloadURL: fmt.Sprintf("http://example.com/%s", snapName),
				},
				Name:      "missing-component",
				Revision:  1,
				Type:      fmt.Sprintf("component/%s", snap.TestComponent),
				Version:   "1.0",
				CreatedAt: "2024-01-01T00:00:00Z",
			},
		}
	}

	goal := snapstate.StoreInstallGoal(snapstate.StoreSnap{
		InstanceName: snapName,
		Components:   []string{compName},
		RevOpts: snapstate.RevisionOptions{
			Channel: channel,
		},
	})

	_, _, err := snapstate.InstallOne(context.Background(), s.state, goal, snapstate.Options{})
	c.Assert(err, ErrorMatches, fmt.Sprintf(`.*cannot find component "%s" in snap resources`, compName))
}

func (s *TargetTestSuite) TestInstallWithComponentsWrongType(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	const (
		snapName = "test-snap"
		compName = "test-component"
		channel  = "channel-for-components"
	)
	s.fakeStore.snapResourcesFn = func(info *snap.Info) []store.SnapResourceResult {
		c.Assert(info.SnapName(), DeepEquals, snapName)

		return []store.SnapResourceResult{
			{
				DownloadInfo: snap.DownloadInfo{
					DownloadURL: fmt.Sprintf("http://example.com/%s", snapName),
				},
				Name:      compName,
				Revision:  1,
				Type:      fmt.Sprintf("component/%s", snap.KernelModulesComponent),
				Version:   "1.0",
				CreatedAt: "2024-01-01T00:00:00Z",
			},
		}
	}

	goal := snapstate.StoreInstallGoal(snapstate.StoreSnap{
		InstanceName: snapName,
		Components:   []string{compName},
		RevOpts: snapstate.RevisionOptions{
			Channel: channel,
		},
	})

	_, _, err := snapstate.InstallOne(context.Background(), s.state, goal, snapstate.Options{})
	c.Assert(err, ErrorMatches, fmt.Sprintf(
		`.*inconsistent component type \("component/%s" in snap, "component/%s" in component\)`, snap.TestComponent, snap.KernelModulesComponent,
	))
}

func (s *TargetTestSuite) TestInstallWithComponentsMissingInInfo(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	const (
		snapName = "test-snap"
		compName = "test-missing-component"
		channel  = "channel-for-components"
	)
	s.fakeStore.snapResourcesFn = func(info *snap.Info) []store.SnapResourceResult {
		c.Assert(info.SnapName(), DeepEquals, snapName)

		return []store.SnapResourceResult{
			{
				DownloadInfo: snap.DownloadInfo{
					DownloadURL: fmt.Sprintf("http://example.com/%s", snapName),
				},
				Name:      compName,
				Revision:  1,
				Type:      fmt.Sprintf("component/%s", snap.TestComponent),
				Version:   "1.0",
				CreatedAt: "2024-01-01T00:00:00Z",
			},
		}
	}

	goal := snapstate.StoreInstallGoal(snapstate.StoreSnap{
		InstanceName: snapName,
		Components:   []string{compName},
		RevOpts: snapstate.RevisionOptions{
			Channel: channel,
		},
	})

	_, _, err := snapstate.InstallOne(context.Background(), s.state, goal, snapstate.Options{})
	c.Assert(err, ErrorMatches, fmt.Sprintf(`.*"%s" is not a component for snap "%s"`, compName, snapName))
}

func (s *TargetTestSuite) TestInstallWithComponentsFromPath(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	const (
		snapName = "test-snap"
		snapID   = "test-snap-id"
		compName = "test-component"
		snapYaml = `name: test-snap
version: 1.0
components:
  test-component:
    type: test
  kernel-modules-component:
    type: kernel-modules
`
		componentYaml = `component: test-snap+test-component
type: test
version: 1.0
`
	)

	snapRevision := snap.R(2)
	si := &snap.SideInfo{
		RealName: snapName,
		SnapID:   snapID,
		Revision: snapRevision,
	}
	snapPath := makeTestSnap(c, snapYaml)

	csi := &snap.ComponentSideInfo{
		Component: naming.NewComponentRef(snapName, compName),
		Revision:  snap.R(3),
	}
	components := map[*snap.ComponentSideInfo]string{
		csi: snaptest.MakeTestComponent(c, componentYaml),
	}

	goal := snapstate.PathInstallGoal(snapName, snapPath, si, components, snapstate.RevisionOptions{})

	info, ts, err := snapstate.InstallOne(context.Background(), s.state, goal, snapstate.Options{})
	c.Assert(err, IsNil)

	c.Check(info.InstanceName(), Equals, snapName)
	c.Check(info.Components[compName].Name, Equals, compName)

	verifyInstallTasksWithComponents(c, snap.TypeApp, localSnap, 0, []string{compName}, ts)
}

func (s *TargetTestSuite) TestUpdateWithComponents(c *C) {
	s.state.Lock()
	defer s.state.Unlock()

	const (
		snapName = "some-snap"
		snapID   = "some-snap-id"
		compName = "test-component"
		channel  = "channel-for-components"
	)

	seq := snapstatetest.NewSequenceFromSnapSideInfos([]*snap.SideInfo{{
		RealName: snapName,
		SnapID:   snapID,
		Revision: snap.R(7),
	}})

	seq.AddComponentForRevision(snap.R(7), &sequence.ComponentState{
		SideInfo: &snap.ComponentSideInfo{
			Component: naming.NewComponentRef(snapName, compName),
			Revision:  snap.R(1),
		},
		CompType: snap.TestComponent,
	})

	s.AddCleanup(snapstate.MockReadComponentInfo(func(
		compMntDir string, info *snap.Info, csi *snap.ComponentSideInfo,
	) (*snap.ComponentInfo, error) {
		return &snap.ComponentInfo{
			Component:         naming.NewComponentRef(info.SnapName(), compName),
			Type:              snap.TestComponent,
			Version:           "1.0",
			ComponentSideInfo: *csi,
		}, nil
	}))

	snapstate.Set(s.state, snapName, &snapstate.SnapState{
		Active:          true,
		TrackingChannel: channel,
		Sequence:        seq,
		Current:         snap.R(7),
		SnapType:        "app",
	})

	s.fakeStore.snapResourcesFn = func(info *snap.Info) []store.SnapResourceResult {
		c.Assert(info.SnapName(), DeepEquals, snapName)

		return []store.SnapResourceResult{
			{
				DownloadInfo: snap.DownloadInfo{
					DownloadURL: fmt.Sprintf("http://example.com/%s", snapName),
				},
				Name:      compName,
				Revision:  2,
				Type:      fmt.Sprintf("component/%s", snap.TestComponent),
				Version:   "1.0",
				CreatedAt: "2024-01-01T00:00:00Z",
			},
		}
	}

	goal := snapstate.StoreUpdateGoal(snapstate.StoreUpdate{
		InstanceName: snapName,
	})

	ts, err := snapstate.UpdateOne(context.Background(), s.state, goal, nil, snapstate.Options{})
	c.Assert(err, IsNil)

	verifyUpdateTasksWithComponents(c, snap.TypeApp, doesReRefresh, 0, []string{compName}, ts)
}
