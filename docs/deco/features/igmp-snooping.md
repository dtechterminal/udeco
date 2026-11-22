# IGMP/MLD snooping on the agent's VLAN bridges

## What the U6 Pro does

`mcsd.conf` and `bridge.conf` set every bridge (`br0`, `br0.<vlan>`) as
follows:

- `multicast_snooping 1`
- mcsd with `policy flood`
- `multicast_querier 0` (written on stop; the bridge never queries itself)
- `hash_max 2048`

## What the agent does

On each VLAN bridge it creates (`br-v<vid>`), the agent sets the same
values through sysfs (`internal/bcmwifi/plan.go` snoopSteps):

- `hash_max 2048`
- `multicast_snooping 1`
- `multicast_querier 0`

A new bridge gets all three. On an existing bridge, only a value that reads
otherwise is written, so Tick puts a drifted value back live. The steps are
optional: a kernel without multicast snooping has no such files, and the
bridge still forwards.

`br-lan` is left to TP-Link's `imsnoop`. Multicast Enhancement remains the
driver's `wmf_bss_enable` (multicast-to-unicast).

With no querier on the VLAN, Linux floods a group until a query is seen.
That matches mcsd's `policy flood` for unknown groups.

## Unverified on hardware

- The three files on the X20's 4.1 kernel, and how snooping interacts with
  the Broadcom flow cache and WMF on a VLAN bridge.

## Garage (platform jio-mtk)

The same three values on each `br-v<vid>` the agent makes on the JCOW414,
written through sysfs at creation and re-asserted by Tick
(`internal/mtkwifi/snoop.go`). The 3.18.21 kernel has bridge multicast
snooping (`br_multicast_*` in its symbols) and floods a group while no querier
is seen. `bdg2` is left to the vendor. The rebuilt MT7603 module has no
IGMP snooping of its own (garage-parity.md section 6). Unverified on the unit.
