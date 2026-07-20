# MFC NDEF Format

A Flipper Zero external app that formats a **MIFARE Classic 1K** into an empty
**NDEF (NFC) tag** — a faithful port of the Proxmark3 `hf mf ndefformat` command.

## Why

The Flipper NFC stack can *read* and *parse* NDEF, but it has no built-in way to
**format** a blank MIFARE Classic as an NDEF tag. Proxmark3 has `hf mf ndefformat`;
the Flipper didn't. This app closes that gap on-device, no Proxmark required.

After formatting, the card presents as a standard NDEF tag — e.g. an iPhone will
surface a formatted MIFARE Classic 1K as a blank NDEF tag, ready to receive
content.

## What it writes

Following the Proxmark algorithm exactly, for a 1K card it:

- writes the **MIFARE Application Directory (MAD)** in sector 0 pointing the NDEF
  AID (`03 E1`) at every sector,
- writes an **empty NDEF TLV** (`03 00 FE`),
- sets the MAD and NDEF **sector-trailer keys and access bits**,
- leaves block 0 (the manufacturer/UID block) untouched.

Keys are chosen automatically: default `FF FF FF FF FF FF` on a blank card, and
the MAD (`A0A1A2A3A4A5` / `89ECA97F8C2A`) + NDEF (`D3F7D3F7D3F7`) keys if the card
is already NDEF-formatted. Each block is written trying key B, then key A.

## Build & install

```sh
ufbt              # build
ufbt launch       # build, upload, and run over USB
```

On the device: **Apps → NFC → MFC NDEF Format → Format 1K as NDEF**, then hold a
card on the back until it reports success.

## Tests

The deterministic layout logic (templates, geometry, key selection) is isolated
in `ndef_layout.c` with no Flipper dependency, and checked on the host against
values transcribed independently from the Proxmark source:

```sh
sh tests/run_tests.sh     # 339 assertions, plain cc
```

## Scope & limitations

- **1K only.** Mini/2K/4K are clean future additions.
- Works on **blank/factory** cards and **re-formats already-NDEF** cards. Cards
  with custom/unknown sector keys will stop with "Write failed at block N".
- Writes an **empty** NDEF format; it does not write NDEF content.
- Also works on blank Gen1a "magic" Classic cards, since it uses only standard
  MIFARE Classic authentication (it does not touch block 0 or use the magic
  backdoor).

## License & attribution

Licensed under **GPL-3.0-or-later** (see the repository [`LICENSE`](../LICENSE)).

The on-card layout logic (the `firstblocks` templates and the write algorithm) is
ported from the Proxmark3 client command `CmdHFMFNDEFFormat`
(`client/src/cmdhfmf.c`) in [`RfidResearchGroup/proxmark3`](https://github.com/RfidResearchGroup/proxmark3),
which is licensed GPL-3.0-or-later. Copyright the Proxmark3 project contributors.
