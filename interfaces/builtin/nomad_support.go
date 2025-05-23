// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package builtin

import "github.com/snapcore/snapd/interfaces"

// The nomad-support interface enables running Hashicorp Nomad within
// a strictly confined snap
// https://www.nomadproject.io/

const nomadSupportSummary = `allows operating as the Hashicorp Nomad service`

const nomadSupportBaseDeclarationPlugs = `
  nomad-support:
    allow-installation: false
    deny-auto-connection: true
`

const nomadSupportBaseDeclarationSlots = `
  nomad-support:
    allow-installation:
      slot-snap-type:
        - core
    deny-auto-connection: true
`

const nomadSupportConnectedPlugAppArmor = `
# Requirements for Nomad service #

# Discovering cgroup info
/sys/fs/cgroup/cgroup.controllers r,
/sys/fs/cgroup/cgroup.subtree_control rw,

# cpuset management top level
/sys/fs/cgroup/nomad.slice/ rw,
/sys/fs/cgroup/nomad.slice/cpuset.cpus.effective r,
/sys/fs/cgroup/nomad.slice/cgroup.type r,

# Required to allow mkdir /sys/fs/cgroup/nomad.slice/
capability dac_override,
# Required to allow chown task_dir to nobody
capability chown,

# managing our own cgroup config
# https://github.com/hashicorp/nomad/issues/18211
/sys/fs/cgroup/nomad.slice/* rw,
/sys/fs/cgroup/nomad.slice/*.slice/{,**} rw,
/sys/fs/cgroup/nomad.slice/*.scope/{,**} rw,

# setting docker cpuset.cpus
# https://github.com/hashicorp/nomad/blob/v1.8.2/drivers/docker/cpuset.go#L21-L24
/sys/fs/cgroup/system.slice/docker-*.scope/cpuset.cpus rw,

# NVIDIA device plugin
# https://developer.hashicorp.com/nomad/plugins/devices/nvidia
@{PROC}/driver/nvidia/capabilities/mig/config r,
@{PROC}/driver/nvidia/capabilities/mig/monitor r,
`

const nomadSupportConnectedPlugSecComp = `
# Description: allow operating as the nomad daemon

# Filesystem syscalls nomad will need, as it allows user to change
# file owner/group arbitrarily.
chown
chown32
fchown
fchown32
fchownat
lchown
lchownat
`

const nomadSupportServiceSnippet = interfaces.PlugServicesServiceSectionSnippet(`Delegate=true`)

type nomadSupportInterface struct {
	commonInterface
}

func init() {
	registerIface(&nomadSupportInterface{commonInterface{
		name:                  "nomad-support",
		summary:               nomadSupportSummary,
		implicitOnClassic:     true,
		implicitOnCore:        true,
		controlsDeviceCgroup:  true,
		baseDeclarationPlugs:  nomadSupportBaseDeclarationPlugs,
		baseDeclarationSlots:  nomadSupportBaseDeclarationSlots,
		connectedPlugAppArmor: nomadSupportConnectedPlugAppArmor,
		connectedPlugSecComp:  nomadSupportConnectedPlugSecComp,
		serviceSnippets:       []interfaces.PlugServicesSnippet{nomadSupportServiceSnippet},
	}})
}
