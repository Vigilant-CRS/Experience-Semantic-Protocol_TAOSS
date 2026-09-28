# Contributing

Thank you for contributing to the Experience Semantic Protocol (ESP/TAOSS)
reference implementation.

## Before you start

1. Read `docs/MASTER_IMPLEMENTATION_PLAN.md`, in particular §1 (rules for
   every work package) and §52a (licensing).
2. Pick the earliest work package that is not `VERIFIED` and whose
   dependencies are `VERIFIED`.
3. Deviations from the plan require an ADR in `docs/decisions/` **in the
   same pull request** (plan §1.3).

## Developer Certificate of Origin (DCO) — required

This project uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
instead of a Contributor License Agreement.

- **You keep your copyright.** There is no copyright assignment and no CLA.
- Every commit must carry a sign-off line matching the commit author:

  ```text
  Signed-off-by: Your Name <your.email@example.org>
  ```

  Use `git commit -s` to add it automatically.
- CI rejects commits without a valid sign-off.

Because there is no CLA, nobody — including the maintainer — can relicense
contributed code under proprietary terms. This is intentional: the core of
ESP stays free (plan §52a).

## Licensing of your contribution

By signing off, you agree that your contribution is licensed under the
license that applies to the path you changed (see `REUSE.toml`):

| Path | License |
|---|---|
| `src/`, `rust/`, `scripts/`, `tests/`, `benchmarks/`, `examples/` | AGPL-3.0-or-later |
| `docs/`, `spec/`, `ontology/` | CC-BY-SA-4.0 |
| `vectors/`, `schemas/` | CC-BY-4.0 |

New source files must start with SPDX headers, for example:

```python
# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
```

Run `reuse lint` before opening a pull request.

## Quality gates

`make verify` must pass locally before a pull request (plan §52).
Do not claim `VERIFIED` for a work package unless its acceptance tests pass.
