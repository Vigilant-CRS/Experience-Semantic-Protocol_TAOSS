# ADR-0023 — Transparency log profile for rotations and DP ledger checkpoints

- Status: PROPOSED (implemented; awaiting maintainer decision). The mechanism,
  including C2SP compatibility, is implemented; who operates the log and the
  witnesses is a maintainer decision.
- Resolves: GAP-019 (mechanism part)
- Work package: WP-053

## Proposal

- Merkle tree exactly as in RFC 9162 §2.1: SHA-256 with leaf prefix 0x00 and
  node prefix 0x01. Inclusion and consistency proofs use the RFC verification
  algorithms. The implementation reproduces the RFC 6962 reference roots.
- Signed tree head: `"esp/v1/tree-head" || tree_size u64 || timestamp_ns u64 || root`,
  signed with Ed25519 by the log key.
- Independent witnesses cosign the same message. Verifiers require a quorum
  of known witnesses, and the log key never counts as its own witness.
- Pre-registered successors are logged as
  `"esp/v1/pre-registered-successor" || old_pk || new_pk` before the rotation
  becomes effective.

## Interoperability with public witnesses (C2SP)

The same tree (same size and RFC 9162 = RFC 6962 root) is also published in the
formats of the public transparency-witness ecosystem, so independent witnesses
can cosign an ESP log without ESP-specific software (`esp.keys.c2sp`):

- **Checkpoint** ([c2sp.org/tlog-checkpoint](https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md)):
  the origin line, the tree size in decimal and the base64 root, optionally
  followed by extension lines. The body is signed as a signed note.
- **Signed note** ([c2sp.org/signed-note](https://github.com/C2SP/C2SP/blob/main/signed-note.md)):
  - an Ed25519 signature line `— <key name> base64(key ID || signature)`;
  - the key ID is `SHA-256(name || 0x0A || 0x01 || public key)[:4]`;
  - the log key name must equal the origin line (ESP profile).
- **Witness cosignature** ([c2sp.org/tlog-cosignature](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md)):
  - an Ed25519 cosignature/v1 (type `0x04`) with signature
    `u64 timestamp || Ed25519(cosignature/v1\n || time <t>\n || checkpoint body)`;
  - verifiers count distinct known witnesses and ignore unknown ones;
  - a failing signature from a known key rejects the note;
  - the log key never counts as a witness;
  - future-dated cosignatures can be refused.
- The ESP `esp/v1/tree-head` format stays valid. A receiver may require either format, or
  both, for the same tree.
- **Test vectors, byte-exact:**
  - the `example.com/foo` vector of c2sp.org/signed-note;
  - the PeterNeumann/EnochRoot vectors of `golang.org/x/mod/sumdb/note`
    ([note_test.go](https://github.com/golang/mod/blob/master/sumdb/note/note_test.go));
  - the cosignature v1 timestamp vector of `transparency-dev/formats`
    ([note_cosigv1_test.go](https://github.com/transparency-dev/formats/blob/main/note/note_cosigv1_test.go)).
  - No public vector for a *verifiable* Ed25519 cosignature/v1 with a known key was
    available. The cosignature signing path is therefore checked against the spec's message
    layout, not against a third-party vector.
- **Not implemented:** ML-DSA-44 cosignatures (`0x06`), which the C2SP spec recommends for
  new deployments.

## Recommended decision (for the maintainer)

This is a recommendation, not a decision. Formal acceptance is the maintainer's.

- **Operator.** The project maintainer (Vigilant e.K.) runs the reference log for the
  public ESP registries (key rotations, registry digests). A deployment that handles
  personal data runs its own log with the same profile.
- **Origin.** A schema-less URL under the operator's domain. The placeholder used in tests
  is `esp.example/registry-log`; the real domain is set at deployment.
- **Witnesses.** At least 3 independent, C2SP-compatible witnesses: witnesses from the
  public witness network plus community or partner witnesses. Neither the log operator nor
  any key it controls is counted.
- **Quorum.**
  - 2-of-3 for L1 profiles.
  - 3-of-5 for L2+ profiles, which carry health or neural data.
- **Algorithm.** Ed25519 now, for compatibility with deployed witnesses. Add ML-DSA-44
  cosignatures once the witness network supports them.
