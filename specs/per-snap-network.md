# Per-snap network isolation

# Abstract
Extend the `network` interface so gadget snaps can expose per-device slots
identified by a `device` attribute, letting application snaps connect through
dedicated namespaces that see only the designated NIC. When such a scoped slot
is connected, snapd will spin up a Linux network namespace for the consuming
snap and bridge a virtual interface inside that namespace to the gadget’s
physical device, ensuring the application only reaches the hardware it was
granted.

# Specification

## Extension of the `network` interface

The existing `network` interface exposes a single implicit slot from the system
snap, giving any connected application visibility of every network device
present on the host. To add per-device isolation, we will extend the interface
so that any `network` slot or plug that declares a `device` attribute is treated
as a specialization targeting a single NIC. The attribute value is the kernel
network interface name (for example `enp3s0`). Sanitization will be updated to
allow gadget snaps to declare `network` slots when they provide the attribute. A
gadget snap would declare per-device `network` slots like this:

```yaml
slots:
  network-enp3s0:
    interface: network
    device: enp3s0
  network-enx7e05cd123456:
    interface: network
    device: enx7e05cd123456
```

Application snaps can either target a specific NIC by defining a `network` plug
with a `device` attribute or omit the attribute to stay compatible with the
implicit system slot. When a plug specifies `device`, snapd will only consider
slots whose attribute matches exactly. When it omits the attribute, the plug can
connect to the implicit system slot or any gadget-provided slot that exposes a
device, and it is up to the administrator to pick which candidate to connect.
The connection could also be defined in the gadget's `gadget.yaml`. An
application that needs the `enp3s0` NIC would declare:

```yaml
plugs:
  dedicated-uplink:
    interface: network
    device: enp3s0
```

The `network` interface’s base declaration must be extended to support
gadget-defined slots. The connection rules also must be expanded so that plugs
can either omit the device attribute (matching either the system-provided and
any gadget-provided `network` slots) or, if they do declare it, the device must
match the slot’s value.

Note that this change introduces ambiguity for auto-connections once the gadget
defines a `network` slot. A plug without a `device` attribute remains eligible
for both the implicit slot and every gadget slot, so snapd sees multiple valid
candidates. When more than one candidate is available, snapd does not
auto-connect and instead requires an explicit selection.

The resulting base declaration fragment for `network` will look like:

```yaml
network:
  allow-installation:
    -
      slot-snap-type:
        - core
    -
      slot-snap-type:
        - gadget
      slot-attributes:
        device: .+
  allow-connection:
    -
      slot-attributes:
        device: $MISSING
      plug-attributes:
        device: $MISSING
    -
      slot-attributes:
        device: .+
      plug-attributes:
        device: $MISSING
    -
      plug-attributes:
        device: $SLOT(device)
  allow-auto-connection:
    -
      slot-attributes:
        device: $MISSING
      plug-attributes:
        device: $MISSING
    -
      slot-attributes:
        device: .+
      plug-attributes:
        device: $MISSING
    -
      plug-attributes:
        device: $SLOT(device)
```

## Network namespace implementation plan

Implementing per-device access requires plumbing a dedicated Linux network
namespace into the confined process. The namespace itself should be prepared
ahead of time when the `network` interface is connected. A snapd helper (or hook
that runs under snapd's control) can create the namespace, move the intended NIC
or a veth/macvlan peer inside it, and bind-mount the resulting namespace
reference inside `/run/snapd/ns/` just like the `.mnt` files used for mount
namespaces (for example, `snap.<instance>.net`). If we want standard tooling
such as `ip netns` to observe the namespace, that reference can also be
re-exported under `/run/netns` via a bind mount, but the authoritative location
remains `/run/snapd/ns/` so snap-confine will use this path to discover which
namespace (if any) to join for each snap instance.

snap-confine already bind-mounts `/run/snapd/ns` (and `/run/netns` for snaps
that have the appropriate interfaces) and runs with the necessary capabilities,
so joining the namespace can be implemented entirely inside
`cmd/snap-confine/snap-confine.c`. After it finishes creating or reusing the
snap’s mount namespace (`sc_populate_mount_ns`) and before it drops capabilities
or execs the workload, it should consult the new metadata (for example via an
environment variable such as `SNAP_NETNS` that snapd sets) to determine whether
a network namespace is required. If so, snap-confine opens
`/run/netns/snap.<instance>.<device>` and calls `setns(fd, CLONE_NEWNET)`. All
the existing AppArmor rules already allow those operations, and no additional
seccomp rules are needed because only snap-confine itself performs the `setns`.

The namespace needs to be cleaned up when the snap or connection disappears.
Extending `snap-discard-ns` is the natural place to do that: after it unmounts
the `.mnt` files it can also unmount and unlink `snap.<instance>.net` namespace
references in `/run/snapd/ns` (and any optional `/run/netns` re-exports) that
belong to the snap, ensuring there are no leaked namespaces or dangling device
assignments. If the metadata is missing or the namespace cannot be opened,
snap-confine should simply skip the `setns` call so that legacy snaps continue
to run in the default network namespace. This approach lets us roll out the
per-device functionality without regressing existing workloads while still
providing the infrastructure needed for gadgets to scope network access to a
specific interface.

## Implementation checklist

- Extend snapd’s network interface handling so that connecting a gadget slot
  creates the dedicated namespace under `/run/netns`, moves or bridges the
  designated device into it, and records metadata under `/run/snapd/ns/` (and
  the snap environment) describing the namespace’s name.
- Teach snap-confine to read that metadata, open the matching namespace handle
  inside the sandbox, and invoke `setns(CLONE_NEWNET)` after its mount namespace
  work but before dropping capabilities or exec’ing the workload.
- Update snap-discard-ns (or a sibling helper) to remove the per-device
  namespaces and associated metadata whenever a snap is removed or the
  connection is torn down, ensuring no netns handles or device assignments leak.
