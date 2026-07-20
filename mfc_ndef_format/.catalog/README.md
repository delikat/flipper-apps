# MFC NDEF Format

Format a blank MIFARE Classic 1K into an empty NDEF (NFC) tag, on-device — a
port of the Proxmark3 `hf mf ndefformat` command.

The Flipper NFC stack reads and parses NDEF, but has no built-in way to *format*
a blank MIFARE Classic as an NDEF tag. This app fills that gap: point it at a
blank (or already NDEF-formatted) 1K card and it writes the MIFARE Application
Directory (MAD) and an empty NDEF record, so the card presents as a standard,
writable NDEF tag — an iPhone, for example, will see it as a blank NDEF tag.

Also works on blank Gen1a "magic" Classic cards, since it uses only standard
MIFARE Classic authentication (it does not touch block 0 or use the magic
backdoor).

**Scope:** 1K only; writes an empty format, not NDEF content. Cards with
custom/unknown sector keys are not supported.

Ported from Proxmark3 (`RfidResearchGroup/proxmark3`), GPL-3.0-or-later.
