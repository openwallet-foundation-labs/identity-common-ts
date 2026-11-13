# Polaris negative vectors for SD-JWT VC presentations

36 SD-JWT VC presentations, each with the verdict it expects, vendored unchanged for
`polaris-negative-vectors.test.ts`. Three are valid controls; each of the others changes
one thing in a control, names the clauses its verdict rests on (RFC 9901, RFC 7515,
SD-JWT VC, OpenID4VP 1.0, Token Status List), and has a class that says how strongly
they require it.

- Source: <https://github.com/EgorKhaklin/polaris-id/tree/37b013f4e7b451f10ea5b6df377337f85f629671/lab/interop/negative-vectors>,
  commit `37b013f4e7b451f10ea5b6df377337f85f629671`
- File: `vectors.json` (version 0.3.1)
- Licence: Apache-2.0, Copyright 2026 Egor Khaklin, in `LICENSE` and `NOTICE` beside this file

The test runs the controls and the vectors of the layers this package verifies: `jose`,
`sd-jwt`, `sd-jwt-vc`, `openid4vp` and `status-list`. The keys and certificates are test
material.

Do not edit these files: replace them with a newer commit from the same repository.
