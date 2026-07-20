## 0.1.0

- Initial release.
- Formats a MIFARE Classic 1K as an empty NDEF (NFC) tag, porting the Proxmark3
  `hf mf ndefformat` algorithm (MAD + empty NDEF TLV, default/MAD/NDEF keys).
- Auto-detects blank vs already-formatted cards; progress + cancel; on-device
  result reporting.
