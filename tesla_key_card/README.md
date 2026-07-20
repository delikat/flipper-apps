# Tesla Key Card (Flipper Zero)

Experimental standalone FAP for Unleashed firmware 089 on Flipper Zero FZ-1/R04.
It implements the Tesla key-card NFC applet flow so the owner can add this
device as a new key through Tesla's normal, driver-authorized pairing flow.

This project does not reuse, copy, or extract an existing key identity. It
generates a fresh P-256 identity and stores it in Flipper application storage.
The stored record is encrypted and integrity-protected with a device-unique
key, but it is not rollback-resistant. Use **Reset identity** before pairing a
replacement device; reset deletes the local identity but cannot revoke the
prior key in the Tesla. Remove the old key through Tesla's normal controls if
you need to revoke it.

Identities created by the original v1 build remain usable for compatibility.
They retain that format until you explicitly reset the identity, which creates
a v2 integrity-protected record and requires pairing the new identity.

## Build and install

From the workspace root:

```sh
cd tesla_key_card
ufbt build
ufbt launch
```

`ufbt launch` requires the Flipper to be connected over USB. The app is an MVP:
the NFC presentation is intentionally limited to ISO-DEP 106 kbit/s, and the
vehicle-specific pairing flow must still be verified on the owner's Model Y.

## Debugging the NFC exchange

The applet advertises a large ISO 14443-4 frame-waiting time (ATS `TB1 = 0xE0`,
FWI 14, roughly 4.9 s) because the AUTHENTICATE reply performs a software P-256
ECDH synchronously on the NFC worker thread, and the firmware listener has no
card-side S(WTX) mechanism — the response must arrive within the advertised FWT
or the reader times out, drops the field, and restarts from SELECT.

Two traces are captured, both showing every frame:

- **On the SD card** (works untethered — present the Flipper at the vehicle,
  then read it back afterward): `/ext/apps_data/tesla_key_card/nfc_debug.log`,
  truncated fresh each launch. Read it with qFlipper's file browser, or:

  ```sh
  ufbt cli        # then: storage read /ext/apps_data/tesla_key_card/nfc_debug.log
  ```

- **Over USB serial** (live, if a host is tethered during the tap): `ufbt cli`,
  then type `log`, and watch the `TeslaNfc` lines.

Each received frame is logged as `RX <n>B [<leading APDU bytes>] SW=<status>
resp=<n>B`, with `ecdh=<N>ms` added on the AUTHENTICATE frame; field-off and
halt events are logged too. This shows exactly what the reader sends and how the
card answers, so the stall point is unambiguous — e.g. whether the vehicle quits
right after SELECT or sends a later command the card rejects. The Flipper screen
also advances Ready → "Tesla is reading card" (SELECT) → "Sending card key..."
(GET PUBLIC KEY) → Authenticated, but the screen only shows the last state per
100 ms tick, so the SD trace is authoritative.

## Tests

```sh
TMPDIR=/private/tmp sh tests/run_tests.sh
```

The host tests cover APDU behavior and independently validate the deterministic
ECDH/SHA-1/AES protocol vector. Target compilation validates the FAP's mbedTLS
and firmware integration; device timing and vehicle pairing still require
on-device validation.

## License & attribution

This app is licensed under **GPL-3.0-or-later**; see the repository
[`LICENSE`](../LICENSE).

It is an independent implementation whose APDU and cryptographic protocol are
referenced from the open-source `gauss-key-card` re-implementation
(Apache License 2.0); see [`NOTICE`](NOTICE). Tesla and Model Y are trademarks of
Tesla, Inc.; this project is unaffiliated.
