# Security Policy

ESP carries consent-bound semantic state. Defects in the wire codec,
cryptographic envelope, nonce handling, consent enforcement, masking or
revocation are treated as **critical**.

## Reporting a vulnerability

Do **not** open a public issue for security defects. Use GitHub's private
vulnerability reporting ("Security" → "Report a vulnerability") on
https://github.com/Vigilant-CRS/Experience-Semantic-Protocol_TAOSS.

Please include affected version/commit, a minimal reproduction and the
impact (for example: masked type recoverable, nonce reuse, acceptance of
a packet that fails the V13 Accept predicate).

## Scope notes

- This is pre-1.0 research software. No component has had an external
  security audit yet (plan WP-044, M11).
- No custom cryptography: primitives come from `cryptography` (OpenSSL)
  and Python's `hashlib` (plan section 29).
- Deletion attestations are signed claims, not proof of erasure (V13 §9.7).
