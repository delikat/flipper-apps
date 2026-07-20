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
