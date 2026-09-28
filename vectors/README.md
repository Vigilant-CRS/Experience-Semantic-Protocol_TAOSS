# ESP conformance vectors

Versioned, deterministic, machine-readable test vectors for independent ESP
implementations (plan WP-021). Licensed **CC BY 4.0** so that any
implementation, including proprietary ones, can test against the same data.

- Suite version: see `INDEX.json` (`suite_version`); every file also carries it.
- `INDEX.json` lists every vector file with its BLAKE2b-256 digest.
- Regenerate with `uv run python scripts/generate_test_vectors.py`; CI checks
  that committed vectors match the generator (`--check`).
- Vectors are produced with fixed keys and inputs. Ed25519 and
  ChaCha20-Poly1305 are deterministic, so outputs are byte-stable.

| File | Content | Spec |
|---|---|---|
| `wire/header_valid.json` | 100-byte headers: minimal, all types, EMO masked, DP level, max lengths | V13 App. A, ADR-0017 |
| `malformed/header_invalid.json` | 17 invalid headers with expected error | V13 App. A, ADR-0017 |
| `wire/latent_valid.json` | TEM latent in F32/F16/INT8_SYM | V13 §8.4 |
| `malformed/latent_invalid.json` | invalid typed latents | V13 §8.4 |
| `crypto/packet_valid.json` | full packet incl. derived keys, timeline tag, nonce | V13 §9.2, ADR-0009/0010 |
| `session/descriptor.json` | session descriptor + digest | ADR-0012 |
| `consent/capabilities.json` | sender capability 0x22, receiver capability 0x21 with/without EMO | V13 §9.7, ADR-0015 |
| `consent/revocation.json` | revocation intent 0x23, deletion attestation 0x24 | V13 §9.7 |
| `identity/bindings.json` | identity proof 0x20, session binding 0x85 | V13 §9.4, ADR-0013 |
| `replay/windows.json` | sequences with expected accept/reject | V13 §9.5, ADR-0016 |

Privacy-accounting (DP) vectors follow with WP-055. Hash-based vectors for
the transparency log use the RFC 6962 reference roots in
`tests/unit/test_keys_revocation.py`.
