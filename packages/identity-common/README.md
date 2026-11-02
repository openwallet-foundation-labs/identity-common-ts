# @owf/identity-common

[![npm version](https://img.shields.io/npm/v/@owf/identity-common)](https://npmjs.com/package/@owf/identity-common)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

The base package of the [Identity Common TypeScript](https://github.com/openwallet-foundation-labs/identity-common-ts) project, providing common types and utilities for identity applications.

## Installation

```bash
# Using npm
npm install @owf/identity-common

# Using pnpm
pnpm add @owf/identity-common

# Using yarn
yarn add @owf/identity-common
```

## Usage

```typescript
import { } from '@owf/identity-common'
```

## Platform Support

This library is **platform agnostic** and works in:

- ✅ Node.js (>=20)
- ✅ Browsers (modern browsers with ES2020 support)
- ✅ React Native

### Requirements

Your environment must provide:

- `URL` and `URLSearchParams` implementations
- A global `fetch` implementation (or provide it via callbacks)
- Global `TextEncoder` and `TextDecoder` implementations

### React Native

When using these libraries in React Native you may need to add a polyfill for `TextDecoder`.

You can confirm this by checking if `global.TextDecoder` is available. It should be available for React Native > 0.85 or Expo SDK > 52.

If it is not available, make sure to add a polyfill like [this one](https://github.com/EvanBacon/text-decoder).

## API Reference

### Validation

Validators of the packages in this project return `{ valid, issues }`. Each issue has a `severity` (`error`, `warning` or `info`), a `code`, a `path` into the validated value, a `message`, and an optional `requirement` and `context`. `valid` is `false` when any issue is an error.

The type of an issue ties each code to its context. The codes of a validator are a closed union, so checking the code narrows the context:

```typescript
for (const issue of result.issues) {
  if (issue.code === 'expired') console.log(issue.context.expiredAt)
}
```

A validator collects its issues with `ValidationIssues`, which checks that each code gets its context. Validators parse with `parseWithSchema(schema, value, { codes })`, which gives the issues of a zod schema as validation issues, with the path zod gives them. Checks in a zod schema add theirs with `addValidationIssue`. The issues zod reports itself get a code of `SCHEMA_VALIDATION_CODES`, with a context:

| Code | When | Context |
| --- | --- | --- |
| `missing` | a required value is absent | |
| `not_allowed` | a value is present that must not be | |
| `invalid_type` | a value has the wrong type | `expected`, e.g. `string` or `int` |
| `invalid_value` | a value is not one of the allowed ones, or matches none of the forms of a union | `allowed`, when the schema lists them |
| `invalid_format` | a string does not have the format | `format`, e.g. `url` |
| `too_small`, `too_big` | a number, length or number of items is out of range | `minimum` or `maximum`, `inclusive`, `origin` |
| `unrecognized_keys` | an object has members the schema does not allow | `keys` |

zod's `custom` code never reaches the issues. A custom issue needs a code of the validator (`codes`) or of `SCHEMA_VALIDATION_CODES`. Without one, `parseWithSchema` throws, as the schema has a check the validator does not list. `zTyp` is a zod schema for a `typ` header that reports an `invalid_typ` issue.

```typescript
import { addValidationIssue, ValidationIssues } from '@owf/identity-common'

const issues = new ValidationIssues<'expired' | 'missing_name'>()
issues.add({ code: 'expired', path: ['exp'], message: 'Expired', context: { expiredAt } })
issues.result() // { valid: false, issues: [...] }

z.object({ exp: z.number(), iat: z.number() }).superRefine((payload, ctx) => {
  if (payload.exp > payload.iat) return
  addValidationIssue(ctx, {
    code: 'expires_before_issued',
    path: ['exp'],
    message: 'exp must be after iat',
    context: { issuedAt: secondsToDate(payload.iat), expiresAt: secondsToDate(payload.exp) },
  })
})
```

When an assert or parse function finds an error, it throws the validation error of its package, e.g. `WRPRCValidationError`, with the `issues` of the validation. It extends the error of the package, e.g. `WRPRCError`, and `validationErrorMessage` builds its message.

## Related Packages

This package is part of the Identity Common TypeScript project:

- `@owf/jose` - JOSE/JWT implementation (planned)
- [`@owf/cose`](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/cose) - COSE/CWT implementation (planned)
- `@owf/x509` - X.509 certificate utilities (planned)

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).
