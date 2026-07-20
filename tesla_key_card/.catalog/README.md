# Tesla Key Card

Experimental Flipper Zero app implementing the Tesla key-card NFC applet flow,
so the owner can add the Flipper as a new key through Tesla's normal,
driver-authorized pairing flow.

It generates a fresh P-256 identity on the Flipper — it does **not** copy or
extract an existing key. The stored identity is encrypted and integrity-protected
with a device-unique key. Use **Reset identity** before pairing a replacement
device; reset deletes the local identity but cannot revoke the prior key in the
vehicle (remove that through Tesla's normal controls).

**MVP:** NFC presentation is intentionally limited to ISO-DEP 106 kbit/s, and the
vehicle-specific pairing flow still requires on-vehicle validation.

Tesla and Model Y are trademarks of Tesla, Inc.; this project is unaffiliated.
