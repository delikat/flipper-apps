# Tesla Key Card — work state & handoff

Branch: **`tesla-key-card-nfc-debug`**. This doc is a cold-start handoff for another
agent/session. It captures where the work stands, what's proven vs. unproven, how to
build/test/measure, and the traps already hit so they aren't re-hit.

---

## 1. Goal

`tesla_key_card/` is a standalone Flipper Zero FAP that **emulates a Tesla key card** so a
Tesla vehicle will pair with it. It is modeled on the **working** `gauss-key-card/` JavaCard
applet (one level up in the workspace, protocol reference only). Success = the car reads the
emulated card and completes pairing.

Protocol (darconeous "Tesla BLE / key card" gist, as implemented in `gauss`):
- ISO 14443-4 (ISO-DEP) card, P-256 ECDH challenge/response.
- `SELECT AID` (`F4 65 73 6C 61 4C 6F 67 69 63`, the phone-key AID) → bare `9000` (no FCI).
- `GET_PUBLIC_KEY` (INS `0x04`) → `04 || X || Y`.
- `AUTHENTICATE` (INS `0x11`) → ECDH(our priv, card-sent peer pub) → `SHA1(shared_x)` →
  AES-128-ECB of `salt(4) || challenge[4:16]`.
- `GET_CARD_INFO` (INS `0x14`) → `{0x00, 0x01}`.

---

## 2. Status at a glance

| Thing | State |
|---|---|
| Builds (`ufbt`, API 87.8) | ✅ green |
| Host test suite | ✅ green (APDU + Python vector + vendored-engine ECDH vector) |
| Fast crypto (this session) | ✅ **built, committed (`e7a33ef`), correctness proven byte-exact** |
| Fast crypto **actual on-device speedup** | ❌ **UNMEASURED** — needs a device launch (no car) |
| Does the car get past SELECT? | ❌ **still the open blocker** — needs a car trip |
| Does AUTHENTICATE succeed end-to-end? | ❌ never reached yet |

---

## 3. The problem, as diagnosed

### 3a. The current blocker: car SELECTs, then quits (needs the car to retest)
On a real Tesla reader the app oscillates "Tesla is reading card" ↔ "Ready", counter
climbing, no feedback on the Tesla screen. On-device SD trace showed **every** cycle is
exactly:
```
RX 15B [00 A4 04 00 0A F4 65 73 6C 61 …] SW=9000 resp=2B   (SELECT ok)
field off                                                   (~500 ms later, forever)
```
i.e. the car SELECTs the F4 AID, gets our bare `9000`, and **quits before `GET_PUBLIC_KEY`**.
It waits only ~500 ms and **ignores our advertised FWT** (and FSCI) — it runs its own fixed
window. So this is an **ISO-DEP activation / ATS** problem, not timing.

**Fix under test (NOT yet retested on the car):** a richer ATS. Was the bare `03 26 E0`;
now **`04 38 77 E1`** (`tesla_nfc.c:49-52`). An official Tesla card's ATS is `05 78 77 91 02`.
ATQA = `04 00`, SAK = `0x20`, 8-byte UID (`tesla_nfc.c:216-220`).

**Do NOT re-add CID (TC1).** A prior commit (`eb503cc`, superseded) added TC1=0x02; review
proved it's a **regression risk, not a fix**: the reader sends *untagged* I-blocks (SELECT
works without CID), and the firmware 4-layer *skips* untagged I-blocks once a non-zero CID is
bound from RATS (`iso14443_4_layer.c`: `cid != NOT_SUPPORTED && cid != 0`). Claiming CID can
only *break* the working SELECT, never unblock. It was dropped again in `552e127`.

### 3b. The likely NEXT blocker: crypto too slow for the ~500 ms window
The startup self-test measured the software ECDH at **~471 ms** (`selftest ecdh=471ms ok=1`).
The firmware NFC listener **cannot send S(WTX)**, and the car uses a fixed ~500 ms window, so
once we DO reach `AUTHENTICATE` the ECDH must finish in ~500 ms or it fails regardless of the
advertised FWT. 471 ms is right on the edge. **That is what the fast-crypto work (below)
addresses.**

`TB1=0xE1` = FWI=14 (~4.9 s advertised), *not* the real card's FWI=9 (~155 ms). We advertise
max FWT deliberately — it's the only lever we have for a slow reply, and the car ignores it
for SELECT anyway. Harmless; keep it.

---

## 4. What was built this session — the fast crypto (commit `e7a33ef`)

**Root cause of the 471 ms:** the shared firmware mbedTLS (`fap_libs=["mbedtls"]`, prebuilt
`~/.ufbt/current/lib/libmbedtls.a`, built from `unleashed-firmware/lib/mbedtls_cfg.h`) is
compiled with `MBEDTLS_NO_64BIT_MULTIPLICATION` + `MBEDTLS_NO_UDBL_DIVISION` **on** (for
portability to 32-bit-only targets). Those force the slow bignum fallbacks on the STM32WB55's
Cortex-M4 (which has the UMAAL 32×32→64 multiply). `MBEDTLS_HAVE_ASM` is on but doesn't save it.

**Fix — vendor our own mbedTLS via `fap_private_libs`:**
- Vendored **mbedTLS 3.6.2** (same version + same 13-file curated set as the firmware) under
  `tesla_key_card/lib/mbedtls/`.
- Built from a FAP-local config `lib/mbedtls/include/mbedtls/mbedtls_config.h` = the firmware's
  `mbedtls_cfg.h` **verbatim except**: `NO_64BIT_MULTIPLICATION` / `NO_UDBL_DIVISION` disabled,
  and `MBEDTLS_ECP_WINDOW_SIZE 6` added.
- Removed `fap_libs=["mbedtls"]`; added the `Lib()` entry in `application.fam`.

**Why it's safe:** this is a **config-only** change — it changes *how* the bignum arithmetic
runs, never *what* it computes → the ECDH output is **bit-identical**. `tesla_crypto.c`'s
algorithm is untouched. Proven, not asserted: `tests/test_ecdh_vector.c` links the **actual
vendored engine** and checks `shared_x == 7cf27b18…` for priv=1/peer=2G (same vector as
`test_crypto_vector.py`). Passes.

**Expected speedup: ~471 ms → ~150–250 ms (theory, UNMEASURED on device).**

### Build mechanics that matter (don't relearn these)
1. `Lib()` **requires** `cflags=["-mword-relocations","-mlong-calls","-Wno-redundant-decls"]`
   — the first two are mandatory for a private lib to link into a FAP (see firmware
   `unleashed-firmware/lib/mbedtls.scons`).
2. All `mbedtls_*` in `unleashed-firmware/targets/f7/api_symbols.csv` are status **`-`**
   (statically linked, NOT loader-exported). So the FAP must be fully self-contained.
   **Verified:** `arm-none-eabi-nm -u` on the built elf shows **zero** undefined `mbedtls_*`
   (`ecdsa.c`'s `asn1_*` refs get `--gc-sections`'d away since we never call ecdsa).
3. Config auto-loads via the default name `mbedtls/mbedtls_config.h` (build_info.h includes it
   when `MBEDTLS_CONFIG_FILE` is undefined) — **no `-D` define needed** anywhere.
4. `sources=["library/*.c"]` globs exactly the 13 vendored `.c`; `lib/` is auto-excluded from
   the app's own `sources`.
5. Host test links only the ECDH closure (bignum, bignum_core, ecp, ecp_curves, platform_util)
   with **relaxed flags** (no `-Werror`/`-pedantic` — mbedTLS isn't clean under them).
   Compiling all 13 on host fails on `asn1_*`, which only the device firmware provides.

### Next crypto lever if 150–250 ms still isn't enough
Define `MBEDTLS_ECP_NO_INTERNAL_RNG` in the vendored config **and** pass `f_rng=NULL` in
`tesla_crypto.c`'s two `mbedtls_ecp_mul` calls → drops point blinding. Output still identical;
~10–20% faster; costs a side-channel countermeasure we don't need against a car reader. Not
done yet (config levers alone should suffice; measure first).

---

## 5. How to build / test / measure

```sh
cd tesla_key_card
ufbt                                   # build the .fap -> dist/
sh tests/run_tests.sh                  # host suite (APDU + Python vector + vendored ECDH vector)
ufbt launch                            # build + upload + run (needs a connected Flipper)
```

**Measure the crypto speed — NO CAR NEEDED:**
1. Install `dist/tesla_key_card.fap`, open the app from the Flipper apps menu (no reader/field).
2. The startup self-test runs immediately (`tesla_key_card.c:551`, on the app thread before
   the NFC listener) and writes to the SD log.
3. Read the log and find: **`selftest ecdh=NNNms ok=1`**.

**Log file:** `APP_DATA_PATH("nfc_debug.log")` → `/ext/apps_data/tesla_key_card/nfc_debug.log`
(`tesla_key_card.c:32`), truncated each launch (`FSOM_CREATE_ALWAYS`), written from the GUI
thread. Same detail streams over `ufbt cli` → `log` (tags `TeslaNfc` / `TeslaCrypto`). On the
dev laptop it's synced to `~/taildrive/nfc_debug.log`.

**Per-frame trace line format** (`tesla_key_card.c:309`):
`RX %uB [preview] SW=%04X resp=%uB ecdh=%ums ev=%s` — `ev=` is an outcome tag
(SELECT / GET_PUBKEY / AUTH / CARD_INFO / PROTO_ERR / TX_ERR / FIELD_OFF / HALT); needed
because a failed send still computes SW=9000, so without it TX_ERR looked like success.

---

## 6. Open items / next steps

1. **Measure the speedup (no car):** launch the new build, capture `selftest ecdh=NNNms`.
   Confirms whether 471 ms actually dropped under ~500 ms with margin.
2. **Car trip:** confirm whether ATS `04 38 77 E1` gets past SELECT to `GET_PUBLIC_KEY`.
   Look for `ev=GET_PUBKEY`, then `ev=AUTH … SW=…` in the log.
3. If the ATS still fails at SELECT: web results say Flipper's ISO14443-4 **card** emulation is
   broadly limited/buggy (many open firmware issues) — may be a firmware wall.
4. If AUTHENTICATE is reached but times out: apply the no-blinding lever (§4).

---

## 7. File map

| File | Layer | Notes |
|---|---|---|
| `tesla_crypto.c` / `.h` | pure logic | P-256 ECDH + SHA1 + AES. **Algorithm faithful to gauss; do not "fix".** Holds the `mbedtls_ct_memcpy_if` shim. |
| `tesla_apdu.c` / `.h` | pure logic | APDU parse/build; host-tested. |
| `tesla_identity.c` / `.h` | key storage | Uses the Flipper secure enclave (`furi_hal_crypto_*`). |
| `tesla_secure.h` | util | `tesla_secure_zero`. |
| `tesla_nfc.c` / `.h` | transport | ISO14443-4a listener, ATS, per-frame event struct (`TeslaNfcEventInfo`). |
| `tesla_key_card.c` | UI | ViewDispatcher, worker, SD trace, startup ECDH self-test, left-button exit. |
| `lib/mbedtls/**` | vendored dep | mbedTLS 3.6.2, perf-tuned config. 170 files. |
| `tests/` | host | `run_tests.sh`, `test_apdu.c`, `test_crypto_vector.py`, `test_ecdh_vector.c`. |
| `application.fam` | manifest | `fap_private_libs=[Lib("mbedtls", …)]`, `stack_size=8*1024`. |

---

## 8. Ruled out (do not re-chase)
- Worker-thread stack overflow (the same ECP mul runs fine at startup on the same 8 KB stack;
  an overflow would `furi_crash`, not oscillate).
- Transport/APDU/CID/PCB/Le bugs (all correct for the non-CID reader that SELECT proves is in use).
- Crypto divergence from gauss (the `salt(4)||challenge[4:16]` overwrite is byte-for-byte
  faithful and pinned by the host vector).

---

## 9. Branch commits (ahead of `origin/master`)
```
e7a33ef  vendor a perf-tuned mbedTLS for ~3x faster P-256 ECDH   <- fast crypto (this session)
21b1039  advertise max FWT (FWI=14), not the real card's FWI=9
552e127  drop CID from ATS; add outcome tags, ATS + ECDH self-timing to trace
eb503cc  present the real Tesla card ATS (was rejected after SELECT)
269abc9  wire the left button to exit
912d93e  trace raw APDU bytes and status word per frame
6634ec0  widen ATS FWT and add on-device NFC diagnostics
```

Environment: ufbt pinned to Unleashed SDK **unlshd-089 / API 87.8**. A precompiled FAP's
embedded API version must match the firmware on the device or the loader rejects it
(`ufbt update` to reconcile). Everything GPL-3.0-or-later; vendored mbedTLS is
Apache-2.0 OR GPL-2.0-or-later (compatible).
