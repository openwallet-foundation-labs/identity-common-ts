# Identity Common TS

Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup, layout and releases. This file lists the rules that are easy to miss.

## Before you finish

Run what CI runs, from the root:

- `pnpm style:fix` and `pnpm md:fix`
- `pnpm types:check`
- `pnpm test packages/<name>` while working, `pnpm test` at the end. Vitest takes paths; `--filter` fails.
- `pnpm packages:check` when a `package.json` changed
- `pnpm build && pnpm esm:check` when exports changed or a package was added

CI installs with `--frozen-lockfile`, so commit `pnpm-lock.yaml` with every dependency change. Versions shared across packages go in the `catalog` of `pnpm-workspace.yaml` and are referenced as `catalog:`.

## Platform and crypto

- Packages never depend on global crypto. It is provided as a callback. `@owf/crypto` is the exception: it is a crypto implementation based on Web Crypto that callers can pass in.
- No Node.js APIs (`Buffer`, `fs`, `node:*`) in package source. Use `Uint8Array` and the encoding helpers of `@owf/identity-common`. `@openid4vc/utils` still uses `Buffer`; don't copy it.
- In `oauth2`, `openid4vci`, `openid4vp` and `openid4vc-utils`, import `URL`, `URLSearchParams`, `fetch`, `Response` and `Headers` from `@openid4vc/utils`. Biome enforces this.

## Schemas and errors

- zod schemas are named `zFoo`.
- Thrown errors are a package exception class that extends `IdentityException`.

## Security

These packages parse and verify credentials, so every input is untrusted.

- Reject what the specification does not allow. A schema that accepts more than the specification is a vulnerability, for example the JAR request schema that matched any object.
- No regular expressions that can backtrack on untrusted input. CodeQL has found ReDoS here before.
- Name the specification and section in comments, tests and changesets, e.g. "OpenID4VP 1.0 Appendix A.2".
- Never discuss a vulnerability in a public issue or PR; see [SECURITY.md](SECURITY.md).

## Tests

- Tests live in `src/__tests__/`. Use the extension the package already uses (`.test.mts` in new packages).
- A fix comes with a test that fails without it. Use the examples and test vectors of the specification where they exist.
- Use msw for HTTP and fast-check for parsers (`*.fuzz.test.ts`).
- Dependencies used only by tests or examples go in the root `devDependencies`.

## Changesets

- Every change to a published package needs a changeset.
- All packages except `dcql` are below 1.0: a feature or breaking change is `minor`, a fix is `patch`. Don't use `major` for them.
- Packages are bumped in fixed groups (`.changeset/config.json`), so one changeset bumps the whole group.
- Write for the user of the package. Name the exported functions and say how their behaviour changes. For a fix, say what was wrong ("Before, …"). Put breaking changes in a `**Breaking:**` paragraph that says how to migrate.

## Commits and pull requests

- Conventional Commits with the package directory as scope, e.g. `fix(oauth2): …` or `feat(eudi-tl): …`, and `feat!:` for breaking changes.
- Write the body as prose: what changes for a user of the package, and why.
- Sign off every commit (`git commit -s`).
- Update the package README when its public API changes.
