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

package asserts

import (
	"errors"
	"fmt"

	"github.com/snapcore/snapd/strutil"
)

// ClusterDevice holds the details about a device in a cluster assertion.
type ClusterDevice struct {
	ID        int
	BrandID   string
	Model     string
	Serial    string
	Addresses []string
}

// ClusterSubcluster holds the details about a subcluster in a cluster
// assertion.
type ClusterSubcluster struct {
	Name    string
	Devices []int
	Snaps   []ClusterSnap
}

// ClusterSnap holds the details about a snap in a subcluster.
type ClusterSnap struct {
	State    string
	Instance string
	Channel  string
}

// Cluster holds a cluster assertion, which describes a cluster of devices and
// their organization into subclusters.
type Cluster struct {
	assertionBase
	seq         int
	devices     []ClusterDevice
	subclusters []ClusterSubcluster
}

// ClusterID returns the cluster's ID.
func (c *Cluster) ClusterID() string {
	return c.HeaderString("cluster-id")
}

// Sequence returns the sequence number of this cluster assertion.
func (c *Cluster) Sequence() int {
	return c.seq
}

// Devices returns the list of devices in the cluster.
func (c *Cluster) Devices() []ClusterDevice {
	return c.devices
}

// Subclusters returns the list of subclusters.
func (c *Cluster) Subclusters() []ClusterSubcluster {
	return c.subclusters
}

var validClusterSnapStates = []string{"clustered", "evacuated", "removed"}

func checkClusterDevice(device map[string]any) (ClusterDevice, error) {
	id, err := checkInt(device, "id")
	if err != nil {
		return ClusterDevice{}, err
	}

	brandID, err := checkNotEmptyString(device, "brand-id")
	if err != nil {
		return ClusterDevice{}, err
	}

	model, err := checkNotEmptyString(device, "model")
	if err != nil {
		return ClusterDevice{}, err
	}

	serial, err := checkNotEmptyString(device, "serial")
	if err != nil {
		return ClusterDevice{}, err
	}

	addresses, err := checkStringList(device, "addresses")
	if err != nil {
		return ClusterDevice{}, err
	}

	return ClusterDevice{
		ID:        id,
		BrandID:   brandID,
		Model:     model,
		Serial:    serial,
		Addresses: addresses,
	}, nil
}

func checkClusterDevices(devices []any) ([]ClusterDevice, error) {
	result := make([]ClusterDevice, 0, len(devices))
	for _, entry := range devices {
		device, ok := entry.(map[string]any)
		if !ok {
			return nil, errors.New(`"devices" field must be a list of maps`)
		}

		d, err := checkClusterDevice(device)
		if err != nil {
			return nil, err
		}

		result = append(result, d)
	}
	return result, nil
}

func checkClusterSnap(snap map[string]any) (ClusterSnap, error) {
	state, err := checkNotEmptyString(snap, "state")
	if err != nil {
		return ClusterSnap{}, err
	}

	if !strutil.ListContains(validClusterSnapStates, state) {
		return ClusterSnap{}, fmt.Errorf("snap state must be one of %v", validClusterSnapStates)
	}

	instance, err := checkNotEmptyString(snap, "instance")
	if err != nil {
		return ClusterSnap{}, err
	}

	// TODO: validate valid instance name

	channel, err := checkNotEmptyString(snap, "channel")
	if err != nil {
		return ClusterSnap{}, err
	}

	// TODO: validate valid channel?

	return ClusterSnap{
		State:    state,
		Instance: instance,
		Channel:  channel,
	}, nil
}

func checkClusterSnaps(snaps []any) ([]ClusterSnap, error) {
	result := make([]ClusterSnap, 0, len(snaps))
	for _, entry := range snaps {
		snap, ok := entry.(map[string]any)
		if !ok {
			return nil, errors.New(`"snaps" field must be a list of maps`)
		}

		s, err := checkClusterSnap(snap)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}

	return result, nil
}

func checkClusterSubcluster(subcluster map[string]any) (ClusterSubcluster, error) {
	name, err := checkNotEmptyString(subcluster, "name")
	if err != nil {
		return ClusterSubcluster{}, err
	}

	devices, err := checkStringList(subcluster, "devices")
	if err != nil {
		return ClusterSubcluster{}, err
	}

	ids := make([]int, 0, len(devices))
	for _, dev := range devices {
		id, err := atoi(dev, "device id %q", dev)
		if err != nil {
			return ClusterSubcluster{}, err
		}
		ids = append(ids, id)
	}

	list, err := checkList(subcluster, "snaps")
	if err != nil {
		return ClusterSubcluster{}, err
	}

	snaps, err := checkClusterSnaps(list)
	if err != nil {
		return ClusterSubcluster{}, err
	}

	return ClusterSubcluster{
		Name:    name,
		Devices: ids,
		Snaps:   snaps,
	}, nil
}

func checkClusterSubclusters(subclusters []any) ([]ClusterSubcluster, error) {
	result := make([]ClusterSubcluster, 0, len(subclusters))
	for _, entry := range subclusters {
		subcluster, ok := entry.(map[string]any)
		if !ok {
			return nil, errors.New(`"subclusters" field must be a list of maps`)
		}

		s, err := checkClusterSubcluster(subcluster)
		if err != nil {
			return nil, err
		}

		result = append(result, s)
	}

	return result, nil
}

func assembleCluster(assert assertionBase) (Assertion, error) {
	_, err := checkNotEmptyString(assert.headers, "cluster-id")
	if err != nil {
		return nil, err
	}

	seq, err := checkSequence(assert.headers, "sequence")
	if err != nil {
		return nil, err
	}

	list, err := checkList(assert.headers, "devices")
	if err != nil {
		return nil, err
	}

	devices, err := checkClusterDevices(list)
	if err != nil {
		return nil, err
	}

	list, err = checkList(assert.headers, "subclusters")
	if err != nil {
		return nil, err
	}

	subclusters, err := checkClusterSubclusters(list)
	if err != nil {
		return nil, err
	}

	return &Cluster{
		assertionBase: assert,
		seq:           seq,
		devices:       devices,
		subclusters:   subclusters,
	}, nil
}
