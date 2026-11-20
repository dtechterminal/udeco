# Transmit power presets

## What the U6 Pro does

The controller sends `radio.N.txpower_mode` (auto, high, medium, low or
custom) and, for custom, `radio.N.txpower` in dBm. A U6 Pro maps these onto
its radio's range:

- high and auto are the radio's maximum for the channel and country;
- low is its minimum;
- medium is halfway between them;
- custom is the controller's dBm within the range.

The U6 Pro reports the power it runs in `tx_power` (the U6 Pro mca-dump
`vap_table` shows 24 and 14 dBm).

## What the agent does

The X20 has one knob, `wl txpwr_degrade`: quarter-dB below the target power,
settable live (`internal/bcmwifi/txpower.go`).

- **Ceiling.** The radio's `txpwr_target_max` read while the degrade is 0.
  This is the board and regulatory limit for the chanspec, which is what
  high transmits. It is kept per radio and chanspec in
  `RunDir/txpwr-ceiling.json`. It is not known whether the target maximum
  moves with the degrade, so a degraded reading never replaces a learnt
  ceiling. A chanspec with no ceiling learnt yet takes the reading plus the
  live degrade once, or, on a channel change, the old chanspec's ceiling.
  It then keeps that value, so a plan never chases its own write.
- **Floor.** 5 dBm (`min_txpower`, the same as the collector's).
- **Presets.** `degrade = (ceiling - target) * 4`:

| Mode | Target |
|---|---|
| auto, high | ceiling |
| medium | (5 + ceiling) / 2 |
| low | 5 dBm |
| custom | the controller's dBm, clamped to [5, ceiling], with a note |

  On 5 GHz (ceiling 23.5 dBm), medium is degrade 37 and low is degrade 74.
  When the ceiling is unknown, medium and low fall back to the old fixed
  3 dB and 6 dB steps.
- **Reporting.** The inform reports `tx_power_mode` as the real preset and
  `tx_power` as the resulting dBm (`Applier.TxPower`, the agent's
  `txPowerFields`). It used to report "custom" and the target maximum.

## Unverified on hardware

- Degrades above 48 (12 dB) have not been checked on an X20. Low on 5 GHz
  needs 74. Whether the PA really reaches 5 dBm, and how linear the step is
  at that depth, is unknown.
- Whether `txpwr_target_max` reflects `txpwr_degrade`. The ceiling cache
  makes the agent independent of the answer.
- The 5 dBm floor is a fixed value. `wl` has no getter for a minimum.
