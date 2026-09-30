# ADR-0026 — SOS encoding

- Status: ACCEPTED (2026-09-30, maintainer decision)
- Resolves: GAP-028
- Work package: WP-064

V13 §16 says only that "SOS uses a 1-bit INT shortcut without EMO/KNO".

Proposal: SOS is the addendum control TLV `0x86` with the one-byte body
`0x01`. It is sent in a control packet (no typed latents, `types_bitmap = 0`)
on the reliable CONTROL channel. Receivers surface it to the application
with priority. It carries no EMO or KNO content and needs no latent consent.
