# flipper-apps

A collection of my [Flipper Zero](https://flipperzero.one/) external apps (FAPs),
built with [`ufbt`](https://github.com/flipperdevices/flipperzero-ufbt). Target
firmware is Unleashed; each app lives in its own subdirectory with its own
`application.fam`.

## Apps

| App | What it does |
|-----|--------------|
| [`mfc_ndef_format`](mfc_ndef_format/) | Format a MIFARE Classic 1K into an empty NDEF (NFC) tag — a port of the Proxmark3 `hf mf ndefformat` command. Fills a gap: the Flipper NFC stack reads and parses NDEF but has no built-in way to *format* a blank Classic as NDEF. |
| [`tesla_key_card`](tesla_key_card/) | Experimental Tesla key-card NFC applet flow, so the owner can add the Flipper as a new key through Tesla's normal, driver-authorized pairing flow. |

## Build & install

From an app directory:

```sh
cd mfc_ndef_format      # or tesla_key_card
ufbt                    # build the .fap
ufbt launch             # build, upload, and run over USB
```

The built `.fap` lands under `dist/`, and (because of the app's `fap_category`)
installs to the SD card under `apps/<category>/`.

## Tests

Apps that have host-testable logic ship a `tests/` directory with a plain-`cc`
runner (no Flipper dependency):

```sh
cd mfc_ndef_format && sh tests/run_tests.sh
```

## License

All apps in this repository are licensed under **GPL-3.0-or-later** — see
[`LICENSE`](LICENSE). `mfc_ndef_format` is a port of Proxmark3
(`RfidResearchGroup/proxmark3`, GPL-3.0-or-later); see its README for details.
