# Auto channel

## What the U6 Pro does

For a radio left on auto (`radio.N.channel=auto`), a U6 Pro's ACS picks a
channel. Nothing is picked from the channels in `radio.N.blklst`
(`block_acs_channel`). On 2.4 GHz the controller's channel plan keeps radios
on 1, 6 and 11.

## What the agent does

TP-Link's `acsd2` is stopped, and bcmwifi keeps an auto radio's live
channel. On top of that, the agent makes one pick
(`cmd/udeco-ap/autochan.go`):

- **When.** Only for a radio the provision's plan restarts anyway
  (`Plan.RadioRestartBand`): the takeover at boot, or a channel, width,
  country or hostapd change of that radio. A 2.4 GHz restart does not give
  the 5 GHz radio a pick, and the other way round. A pick never causes a
  restart of its own and is never repeated periodically. It holds for the agent's run, unless it stops
  qualifying (blocked, or no longer allowed).
- **Candidates.** The driver's channel list for the radio's width in the
  country (`wl.Caps`; the static list 1/6/11 and 36–48/149–161 when the caps
  are for another country), then:
  - on 2.4 GHz, only 1, 6 or 11;
  - on 5 GHz, no DFS channel, because a CAC and radar moves are for a
    channel the controller chose;
  - never a channel in `radio.N.blklst` (translate `RadioIntent.Blocked`,
    comma or space separated).
- **Score.** Lowest wins:
  - each neighbour from the last scan whose span overlaps the candidate's
    span adds `signal + 95`, so louder neighbours count more;
  - each 20 MHz channel in the candidate's block adds its utilization from
    the spectrum table (the live table, else the one saved on flash).

  A tie keeps the live channel, then the lowest channel.

## Unverified on hardware

- The `blklst` format. The U6 strings show `radio.%d.blklst` handed to
  `block_acs_channel -band %d %s`; a list of channels is assumed.
- How good the pick is. At boot the scan and spectrum data are often only
  what was saved on flash, or nothing, in which case the live channel (or
  the lowest candidate) is kept.
