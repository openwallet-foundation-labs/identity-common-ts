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
- Web APIs can only be used if they're supported in Node.JS (the versions this repo supports), React Native (at least the last few versions), and Browsers (should be a good tradeoff in compatibility, we don't have to support IE, but also not only the latest Chrome)

## Schemas and errors

- zod schemas are named `zFoo`.
- Thrown errors are a package exception class that extends `IdentityException`.

## Writing code

- Make the smallest change that solves the whole task, including the callers and tests it affects.
- Reuse before you write: what the package has, then `@owf/identity-common`, the platform, and a dependency the package already uses. Don't add a dependency for a few lines.
- No abstractions, options or configuration nobody asked for. Follow the structure of the surrounding code and the naming rules in [CONTRIBUTING.md](CONTRIBUTING.md#naming).
- Comment only what the code can't show: why it does something, or the requirement of the specification it implements. Don't comment self-explanatory code. Exported functions and types get JSDoc.
- Shorter code must not drop a check: keep the validation of untrusted input and the error handling.

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
- Keep changesets short and write them for the user of the package: name the exported functions and say what changes for them, or for a fix, what was wrong. A breaking change adds a `**Breaking:**` paragraph on how to migrate.

## Commits and pull requests

- Conventional Commits with the package directory as scope, e.g. `fix(oauth2): …` or `feat(eudi-tl): …`, and `feat!:` for breaking changes.
- Write the body as prose: what changes for a user of the package, and why.
- Sign off every commit (`git commit -s`).
- Don't add AI attribution, such as a `Co-Authored-By` trailer for an AI or a "Generated with" line, to commits or pull requests. The contributor is responsible for the change, however it was written.
- Update the package README when its public API changes.
