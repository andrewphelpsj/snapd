// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2018 Canonical Ltd
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

package builtin_test

import (
	"fmt"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/apparmor"
	"github.com/snapcore/snapd/interfaces/builtin"
	"github.com/snapcore/snapd/interfaces/seccomp"
	"github.com/snapcore/snapd/interfaces/udev"
	"github.com/snapcore/snapd/release"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type AudioPlaybackInterfaceSuite struct {
	iface           interfaces.Interface
	coreSlotInfo    *snap.SlotInfo
	coreSlot        *interfaces.ConnectedSlot
	classicSlotInfo *snap.SlotInfo
	classicSlot     *interfaces.ConnectedSlot
	plugInfo        *snap.PlugInfo
	plug            *interfaces.ConnectedPlug
}

var _ = Suite(&AudioPlaybackInterfaceSuite{
	iface: builtin.MustInterface("audio-playback"),
})

const audioPlaybackMockPlugSnapInfoYaml = `name: consumer
version: 1.0
apps:
 app:
  command: foo
  plugs: [audio-playback]
`

// an audio-playback slot on a audio-playback snap (as installed on a core/all-snap system)
const audioPlaybackMockCoreSlotSnapInfoYaml = `name: audio-playback
version: 1.0
apps:
 app1:
  command: foo
  slots: [audio-playback]
`

// an audio-playback slot on the core snap (as automatically added on classic)
const audioPlaybackMockClassicSlotSnapInfoYaml = `name: core
version: 0
type: os
slots:
 audio-playback:
  interface: audio-playback
`

func (s *AudioPlaybackInterfaceSuite) SetUpTest(c *C) {
	s.coreSlot, s.coreSlotInfo = MockConnectedSlot(c, audioPlaybackMockCoreSlotSnapInfoYaml, nil, "audio-playback")
	s.classicSlot, s.classicSlotInfo = MockConnectedSlot(c, audioPlaybackMockClassicSlotSnapInfoYaml, nil, "audio-playback")
	s.plug, s.plugInfo = MockConnectedPlug(c, audioPlaybackMockPlugSnapInfoYaml, nil, "audio-playback")
}

func (s *AudioPlaybackInterfaceSuite) TestName(c *C) {
	c.Assert(s.iface.Name(), Equals, "audio-playback")
}

func (s *AudioPlaybackInterfaceSuite) TestSanitizeSlot(c *C) {
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.coreSlotInfo), IsNil)
	c.Assert(interfaces.BeforePrepareSlot(s.iface, s.classicSlotInfo), IsNil)
}

func (s *AudioPlaybackInterfaceSuite) TestSanitizePlug(c *C) {
	c.Assert(interfaces.BeforePreparePlug(s.iface, s.plugInfo), IsNil)
}

func (s *AudioPlaybackInterfaceSuite) TestSecComp(c *C) {
	restore := release.MockOnClassic(false)
	defer restore()

	// connected plug to core slot
	spec := seccomp.NewSpecification(s.plug.AppSet())
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, s.coreSlot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "shmctl\n")

	// connected core slot to plug
	spec = seccomp.NewSpecification(s.coreSlot.AppSet())
	c.Assert(spec.AddConnectedSlot(s.iface, s.plug, s.coreSlot), IsNil)
	c.Assert(spec.SecurityTags(), HasLen, 0)

	// permanent core slot
	spec = seccomp.NewSpecification(s.coreSlot.AppSet())
	c.Assert(spec.AddPermanentSlot(s.iface, s.coreSlotInfo), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.audio-playback.app1"})
	c.Assert(spec.SnippetForTag("snap.audio-playback.app1"), testutil.Contains, "listen\n")
}

func (s *AudioPlaybackInterfaceSuite) TestSecCompOnClassic(c *C) {
	restore := release.MockOnClassic(true)
	defer restore()

	// connected plug to classic slot
	spec := seccomp.NewSpecification(s.plug.AppSet())
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, s.classicSlot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Check(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "shmctl\n")

	// connected classic slot to plug
	spec = seccomp.NewSpecification(s.classicSlot.AppSet())
	c.Assert(spec.AddConnectedSlot(s.iface, s.plug, s.classicSlot), IsNil)
	c.Assert(spec.SecurityTags(), HasLen, 0)

	// permanent classic slot
	spec = seccomp.NewSpecification(s.classicSlot.AppSet())
	c.Assert(spec.AddPermanentSlot(s.iface, s.classicSlotInfo), IsNil)
	c.Assert(spec.SecurityTags(), HasLen, 0)
}

func (s *AudioPlaybackInterfaceSuite) TestAppArmor(c *C) {
	restore := release.MockOnClassic(false)
	defer restore()

	// connected plug to core slot
	spec := apparmor.NewSpecification(s.plug.AppSet())
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, s.coreSlot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Check(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "/{run,dev}/shm/pulse-shm-* mrwk,\n")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "owner /run/user/[0-9]*/snap.audio-playback/pulse/ r,\n")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "owner /run/user/[0-9]*/snap.audio-playback/pulse/native rwk,\n")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "owner /run/user/[0-9]*/snap.audio-playback/pulse/pid r,\n")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "owner /var/snap/audio-playback/common/pulse/ r,\n")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "owner /var/snap/audio-playback/common/pulse/native rwk,\n")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "owner /var/snap/audio-playback/common/pulse/pid r,\n")

	// connected core slot to plug
	spec = apparmor.NewSpecification(s.coreSlot.AppSet())
	c.Assert(spec.AddConnectedSlot(s.iface, s.plug, s.coreSlot), IsNil)
	c.Assert(spec.SecurityTags(), HasLen, 0)

	// permanent core slot
	spec = apparmor.NewSpecification(s.coreSlot.AppSet())
	c.Assert(spec.AddPermanentSlot(s.iface, s.coreSlotInfo), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.audio-playback.app1"})
	c.Check(spec.SnippetForTag("snap.audio-playback.app1"), testutil.Contains, "capability setuid,\n")
	c.Check(spec.SnippetForTag("snap.audio-playback.app1"), testutil.Contains, "/etc/pulse/ r,\n")
	c.Check(spec.SnippetForTag("snap.audio-playback.app1"), testutil.Contains, "/etc/pulse/** r,\n")
}

func (s *AudioPlaybackInterfaceSuite) TestAppArmorOnClassic(c *C) {
	restore := release.MockOnClassic(true)
	defer restore()

	// connected plug to classic slot
	spec := apparmor.NewSpecification(s.plug.AppSet())
	c.Assert(spec.AddConnectedPlug(s.iface, s.plug, s.classicSlot), IsNil)
	c.Assert(spec.SecurityTags(), DeepEquals, []string{"snap.consumer.app"})
	c.Check(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "/{run,dev}/shm/pulse-shm-* mrwk,\n")
	c.Check(spec.SnippetForTag("snap.consumer.app"), testutil.Contains, "/etc/pulse/ r,\n")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), Not(testutil.Contains), "owner /run/user/[0-9]*/snap.audio-playback/pulse/ r,\n")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), Not(testutil.Contains), "owner /run/user/[0-9]*/snap.audio-playback/pulse/native rwk,\n")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), Not(testutil.Contains), "owner /run/user/[0-9]*/snap.audio-playback/pulse/pid r,\n")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), Not(testutil.Contains), "owner /var/snap/snap.audio-playback/common/pulse/r,\n")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), Not(testutil.Contains), "owner /var/snap/snap.audio-playback/common/pulse/native rwk,\n")
	c.Assert(spec.SnippetForTag("snap.consumer.app"), Not(testutil.Contains), "owner /var/snap/snap.audio-playback/common/pulse/pid r,\n")

	// connected classic slot to plug
	spec = apparmor.NewSpecification(s.classicSlot.AppSet())
	c.Assert(spec.AddConnectedSlot(s.iface, s.plug, s.classicSlot), IsNil)
	c.Assert(spec.SecurityTags(), HasLen, 0)

	// permanent classic slot
	spec = apparmor.NewSpecification(s.classicSlot.AppSet())
	c.Assert(spec.AddPermanentSlot(s.iface, s.classicSlotInfo), IsNil)
	c.Assert(spec.SecurityTags(), HasLen, 0)

	c.Check(spec.SnippetForTag("snap.audio-playback.app1"), Not(testutil.Contains), "/etc/pulse/ r,\n")
	c.Check(spec.SnippetForTag("snap.audio-playback.app1"), Not(testutil.Contains), "/etc/pulse/** r,\n")
}

func (s *AudioPlaybackInterfaceSuite) TestUDev(c *C) {
	spec := udev.NewSpecification(s.coreSlot.AppSet())
	c.Assert(spec.AddPermanentSlot(s.iface, s.coreSlotInfo), IsNil)
	c.Assert(spec.Snippets(), HasLen, 4)
	c.Assert(spec.Snippets(), testutil.Contains, `# audio-playback
KERNEL=="controlC[0-9]*", TAG+="snap_audio-playback_app1"`)
	c.Assert(spec.Snippets(), testutil.Contains, `# audio-playback
KERNEL=="pcmC[0-9]*D[0-9]*[cp]", TAG+="snap_audio-playback_app1"`)
	c.Assert(spec.Snippets(), testutil.Contains, `# audio-playback
KERNEL=="timer", TAG+="snap_audio-playback_app1"`)
	c.Assert(spec.Snippets(), testutil.Contains, fmt.Sprintf(`TAG=="snap_audio-playback_app1", SUBSYSTEM!="module", SUBSYSTEM!="subsystem", RUN+="%v/snap-device-helper $env{ACTION} snap_audio-playback_app1 $devpath $major:$minor"`, dirs.DistroLibExecDir))
}

func (s *AudioPlaybackInterfaceSuite) TestInterfaces(c *C) {
	c.Check(builtin.Interfaces(), testutil.DeepContains, s.iface)
}
