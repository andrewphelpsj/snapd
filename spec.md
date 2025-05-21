# Cluster Assemble Protocol

The intent of the cluster assemble protocol is to establish trust across a set of devices and
proliferate knowledge of the graph of devices to all devices in the cluster so that all participants
have a consistent view of the state of the cluster.

## Terminology
- `RDT(device)` - Cryptographically secure Random Device Token (RDT) for device.
- `secret` - The shared secret used in the assemble session.
- `CERT(device)` - The TLS certificate for device.
- `FP(device)` - The TLS certificate fingerprint for device (the sha512 of `CERT(device)`).
- `SERIAL(device)` - The serial assertion for device. This contains the device's public key.
- `SIGN(device, data)` - Arbitrary signed data, signed using the device's private key.
- `HMAC(a, b, c...)` - sha512 of a byte-representation of all given arguments.
- `ADDRESS(device)` - An address that device can be reached at , in the form "ip:port".

## Overview

The assemble protocol is meant to discover a fully connected graph of devices. Initial trust will be
established by a shared secret that we can assume all devices participating in the assemble session
can access. Initially, all devices in the cluster will use mDNS to broadcast their presence and
address to their peers.

All devices will attempt to establish a connection with all other devices that they have discovered.
The design of the protocol requires that connections use TLS; the certificates will be used to help
establish trust in the cluster. Once connected, mutual authentication is established via the HMAC of
the shared secret. After a device has proved its knowledge of the shared secret, data that
originates from a peer using that TLS certificate can be trusted and associated with that peer*.
This initial message used to establish mutual authentication will also include an RDT (random device
token) that is used to identify the device.

Mutually authenticated devices will continually publish their knowledge of the state of the
cluster's connectivity to each other. Specifically, a device will publish their knowledge of the
graph of devices participating in the assemble session. This graph will include edges that the
publishing device has directly verified in addition to edges that other peers have reported to the
publishing device.

As a device receives updates to the state of the graph from its peers, the receiving device will
check if the graph includes any devices for which it has not yet received identifying information.
The receiving device will request identifying information for all unrecognized devices from the peer
that sent the update to the graph. This identifying information will be cross-checked when the
receiving device attempts to connect to the previously unrecognized device*. Once a device has
received identifying information for both devices in an edge, then the receiving device should
publish that edge to other peers that have not yet seen that edge.

As this process is happening, information about the state of the cluster will be reported to the
user via terminal output. Since each device retains knowledge of every other device's view of the
cluster, inconsistencies and missing edges can be reported to the user. Once the user is satisfied
with the state of the cluster, the process can be terminated and the state of the cluster can be
exported.

## mDNS Discovery

Devices in the cluster will open themselves up to discovery to the rest of the cluster using mDNS.
Each device participating in the assemble session will advertise themselves using the service type
`_snapd._tcp`. Note that this string is arbitrary, we could pick anything. Devices will advertise
the IP addresses at which they can be reached, as well as their listening port.

After a device starts its local mDNS server, it will then begin to query for other devices on an
interval. Polling for new devices will continue until the assemble protocol is ended by the user.
For each device that is discovered, mutual authentication will be attempted; successfully
authenticated devices will be treated as a participant for the remainder of the assemble session.

## Protocol Messages

After device discovery, devices will exchange messages to both establish trust and proliferate
information about the cluster to other participating devices. Each message's format and utility is
described here.

While no specific application-layer protocol is required by the assemble protocol, this document
describes the protocol as if each device is running an HTTPS server that will be used for all
inter-device communication. Note that HTTPS is required, rather than just HTTP, as the encrypted
traffic is important to the security of the protocol, and TLS certificates themselves play a role in
the protocol. Note that a device must use the same TLS certificate for its HTTPS server as it uses
to establish any outbound connections to other device servers, since that certificate is tied to the
device's identity.

### assemble-auth

The `assemble-auth` message is used to establish mutual authentication between two devices. These
messages must be exchanged before any other information.

```
POST /assemble/auth
{
  "hmac": HMAC(secret, FP(device), RDT(device)),
  "rdt": RDT(device),
}

---

200 OK
{
  "hmac": HMAC(secret, FP(device), RDT(device)),
  "rdt": RDT(device),
}
```

The `hmac` field in this message contains a hash of the shared secret, the device's TLS certificate
fingerprint, and the device's RDT. A receiving device can verify the sending device's knowledge of
the shared secret, since all other pieces of the HMAC are provided. The RDT is given in the message
itself in the `rdt` field, and the device's TLS certificate is provided due to the nature of the TLS
connection.

Once these messages are exchanged, data that arrives via a connection that uses
the received TLS certificate can be trusted and associated with the RDT provided
in the original message. Other routes will drop any attempted connections from
unknown TLS certificates.

This route is unique due to the fact that it includes a response body. While not required for the
protocol to function, this simplifies the process required to achieve mutual trust*.

Once authenticated, each device gets into a loop that performs the following tasks:
1. Send changes to the graph to each trusted peer, via `assemble-routes` messages.
1. Accept updates to the graph from peers, via `assemble-routes` messages.
1. Request identifying information for unknown devices, via `assemble-unknown-devices` messages.
1. Respond to `assemble-unknown-devices` messages, via `assemble-devices` messages.

### assemble-routes

The `assemble-routes` message is used to spread knowledge about the state of the cluster from one
device to another. This is the first message that will be sent to a device following the successful
exchange of `assemble-auth` messages.

```
POST /assemble/routes
{
  "devices": [
    RDT(A),
    RDT(B),
    ...
  ],
  "addresses": [
    ADDRESS(A),
    ADDRESS(B),
    ...
  ],
  "routes": [
    0, 1, 0,
    ...
  ],
}

---

200 OK
```

The `devices` field contains a list of RDTs for which the sending device has identifying
information. There is one notable exception: `devices` will always contain the RDT of the receiving
device, since it should have identifying information for itself.

The `addresses` field contains a list of addresses, which can be thought of as edges in the graph of
devices.

The `routes` field contains a representation of the verified routes in the graph. The list is a
flattened list of triplets. The first and second values in a triplet are indices into the `devices`
list. The third value in the triplet is an index into the `addresses` list. For a more formal
definition: `devices[routes[n]]` has established a connection to the `devices[routes[n+1]]` via
`address[routes[n+2]]`.

Note that the `addresses` list can contain addresses that are not yet part of the graph, because no
connection has been initiated to that address yet. As an example, when the very first
`assemble-routes` message is sent, it will contain the address of the receiving device, which **is**
a part of the graph. Additionally, it will also contain the address of the sending device, which
**is not yet** a part of the graph. In the above snippet, this is an example of device `A` sending
the first `assemble-routes` message to device `B`. When device `B` sends an `assemble-routes` to
device `A`, it will include the additional route `1, 2, 1`.

NOTE: Expand more about the potential for multiple addresses used as a route to a with a device
here.

### assemble-unknown-devices

The `assemble-unknown-devices` message is used to request identifying information about a set of
devices from the receiving device. It is generally sent in response to an `assemble-routes` message
that contains RDTs that the sending device has not yet seen.

```
POST /assemble/unknown
{
  "devices": [
    RDT(B),
    RDT(C),
    ...
  ]
}
---

200 OK
```

The receipt of a `assemble-unknown-devices` message should result in the receiving device sending an
`assemble-devices` message.

### assemble-devices

The `assemble-devices` message contains identifying information for a set of trusted devices in the
cluster.

```
{
  "devices": [
    {
      "rdt": RDT(B),
      "cert": CERT(B),
      "serial": SERIAL(B),
      "serial-proof": SIGN(B, HMAC(secret, FP(B), RDT(B))),
    },
    {
      "rdt": RDT(C),
      "cert": CERT(C),
      "serial": SERIAL(C),
      "serial-proof": SIGN(C, HMAC(secret, FP(C), RDT(C))),
    },
    ...
  ]
}
```

The signed HMAC given in `serial-proof` proves that the device with the given serial assertion both
intends and is allowed to participate in the assemble session, and ensures that the whole cluster
has a consistent idea of which certificate should be used to communicate with the device, no matter
the address or the route. The signature may be performed only once per device for the entire
duration of the assemble session.

The security of this is reliant on the fact that it is difficult to fabricate a serial assertion,
since it is signed by a private key that is not present on any of the devices in the cluster*.

Question: The other spec defines `cert` as `CERT(device)`. Could this be `FP(device)`, to be more
analogous to `assemble-auth` messages?

## Footnotes

*Statements that I'm making that I want to make sure are true.
