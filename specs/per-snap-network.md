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
  nic-enp3s0:
    interface: network
    device: enp3s0
  nic-usb0:
    interface: network
    device: enx7e05cd123456
```

Application snaps can either target a specific NIC by defining a `network` plug
with a `device` attribute or omit the attribute to stay compatible with the
implicit system slot. When a plug specifies `device`, snapd will only consider
slots whose attribute matches exactly. When it omits the attribute, the plug can
connect to the implicit system slot or any gadget-provided slot that exposes a
device, and it is up to the administrator to pick which candidate to connect.
An application that needs the `enp3s0` NIC would declare:

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
