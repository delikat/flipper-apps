# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository

`flipper-apps` — a monorepo of Flipper Zero external apps (FAPs), built with `ufbt`, all
GPL-3.0-or-later. Each app is a self-contained subdirectory with its own `application.fam`:

- `mfc_ndef_format/` — formats a MIFARE Classic 1K as an empty NDEF tag; a port of the
  Proxmark3 `hf mf ndefformat` command.
- `tesla_key_card/` — experimental Tesla key-card NFC applet flow (links `mbedtls`).

## Build & run

```sh
cd mfc_ndef_format        # or tesla_key_card
ufbt                      # build the .fap -> dist/
ufbt launch               # build, upload, run over USB (needs a connected Flipper)
```

`ufbt` targets the Unleashed SDK (API 87.8 / unlshd-089). A precompiled FAP's embedded API
version must match the firmware on the device or the loader rejects it; `ufbt update` to
reconcile.

## Tests (host, no device or Flipper dependency)

```sh
sh mfc_ndef_format/tests/run_tests.sh    # 339 assertions, plain cc
sh tesla_key_card/tests/run_tests.sh     # APDU C tests + a Python crypto vector
```

Each `run_tests.sh` compiles the app's pure-logic files with `cc` and runs asserting
binaries. Suites are monolithic (one binary of asserts) — there is no per-assertion runner;
edit the test file to iterate on a single case.

## CI

`.github/workflows/ci.yml` — GitHub Actions, first-party actions only (`actions/checkout`,
`actions/setup-python`); no third-party. Runs both host suites and builds each FAP with
ufbt. The SDK pin uses `ufbt update --hw-target=f7 --url=<unlshd-089 SDK zip>` —
`--hw-target=f7` is required alongside `--url`.

## App architecture (pattern shared by both apps)

Three layers, split deliberately:

1. **Pure logic, zero Flipper dependency** — its own file, host-tested in `tests/`
   (`mfc_ndef_format/ndef_layout.c`; `tesla_key_card/tesla_apdu.c`, `tesla_crypto.c`).
   Keep new deterministic logic here so it stays host-testable.
2. **NFC transport** — uses the blocking synchronous poller API (e.g.
   `mf_classic_poller_sync_*`). Each sync call is a full activate→auth→op→halt field cycle
   and blocks, so it must run on a worker thread, never the GUI thread
   (`mfc_ndef_format/ndef_format.c`).
3. **UI** — `ViewDispatcher` + `Submenu`/`Popup`/`Widget`, with a `FuriThread` worker that
   runs layer 2 and reports progress/results via `view_dispatcher_send_custom_event`
   (`mfc_ndef_format/mfc_ndef_format.c`).

FAPs are EXTERNAL apps and may only call firmware symbols exported to FAPs. Confirm a symbol
is exported before calling it from a FAP — status `+` in the Unleashed firmware's
`targets/f7/api_symbols.csv` (the `unleashed-firmware/` reference clone one level up, and
mirrored under `~/.ufbt/current/sdk_headers/f7_sdk/`).

## Conventions

- Default branch is `master`. Match existing conventions; do not rename or restructure
  defaults unprompted.
- All apps are GPL-3.0-or-later (root `LICENSE`). `mfc_ndef_format` ports GPL Proxmark code
  — keep its SPDX headers and Proxmark attribution. `tesla_key_card` was relicensed from
  Apache-2.0 to GPLv3.
- App-catalog assets are staged under `<app>/.catalog/`, but submission still needs a
  per-app `fap_icon` (10×10 PNG in `application.fam`) and real screenshots.
