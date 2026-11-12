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
- A global `fetch` implementation (or provide it via callbacks), and global `Headers` and `Response`
- Global `TextEncoder` and `TextDecoder` implementations

### React Native

When using these libraries in React Native you may need to add a polyfill for `TextDecoder`.

You can confirm this by checking if `global.TextDecoder` is available. It should be available for React Native > 0.85 or Expo SDK > 52.

If it is not available, make sure to add a polyfill like [this one](https://github.com/EvanBacon/text-decoder).

The `fetch` of React Native without Expo does not stream the body of a response, so a response is read whole before its size can be checked. Use a `fetch` that streams the body, such as the one of Expo (`expo/fetch`) or [`react-native-nitro-fetch`](https://github.com/margelo/react-native-nitro-fetch), so that the packages stop reading a response once it is larger than its limit (see [Fetching](#fetching)).

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
| `missing_value` | a required value is absent | `expected`, e.g. `string` |
| `not_allowed` | a value is present that must not be | |
| `invalid_type` | a value has the wrong type | `expected`, e.g. `string` or `int` |
| `invalid_value` | a value is not one of the allowed ones, or matches none of the forms of a union | `allowed`, when the schema lists them, and `branches`, the issues of each form of a union |
| `invalid_format` | a string does not have the format | `format`, e.g. `url` |
| `too_small`, `too_big` | a number, length or number of items is out of range | `minimum` or `maximum`, `inclusive`, `origin` |
| `unrecognized_keys` | an object or map has members the schema does not allow | `keys`, as in the value |

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

When an assert or parse function finds an error, it throws the validation error of its package, e.g. `RegistrationCertificateValidationError`, with the `issues` of the validation. It extends `ValidationError`, so `instanceof ValidationError` catches the validation errors of every package, and `validationErrorMessage` builds its message.

`parseWithSchema` returns a `SchemaParseResult`: `{ success: true, data }` or `{ success: false, issues }`. `parseWithErrorHandling(schema, value, message)` parses without `codes` and throws a `ValidationError` with the issues. The message lists the errors with their path, never the parsed value. A union that no member matches lists its members as numbered options, each with its errors. Give the members a label, e.g. the version of a specification, with `unionParams`:

```typescript
import { unionParams } from '@owf/identity-common'

const zMetadata = z.union([zMetadataV1, zMetadataDraft11], unionParams('Invalid metadata', ['version 1.0', 'draft 11']))
```

`zTyp('dpop+jwt')` validates a JOSE `typ` header and `isJwtTyp(typ, 'dpop+jwt')` compares one. Both accept the `typ` in any casing and with the `application/` prefix (RFC 7515 Section 4.1.9), so compare a parsed `typ` with `isJwtTyp`, not with `===`.

`isMediaType(contentType, CommonMediaTypes.Json)` compares a `Content-Type` value with one or more media types, ignoring casing and parameters (RFC 9110 Section 8.3), so `application/json; charset=utf-8` matches and `application/json-seq` does not. `extractMediaType` returns the normalized `type/subtype`, and `createAcceptHeader` builds an `Accept` header with quality values in order of preference. `CommonMediaTypes` has the media types that are not specific to one specification, such as `Json`, `Jwt` and `JwkSet`.

### Fetching

The packages of this repository fetch through `fetchWithLimits`, which reads the body of every response within a maximum size. They take a `fetch` (`FetchCallback`) and `fetchLimits` (`FetchLimits`), and pass them on. Each package defines the types of what it fetches, e.g. `MdocFetchType` of `@owf/mdoc` or `Openid4vcFetchType` of `@openid4vc/utils`, so a callback passed to a package only gets the types of that package:

```typescript
import type { FetchCallback, FetchLimits } from '@owf/identity-common'

// Gets what is fetched as its third argument, e.g. to apply a timeout or a cache per type. The global fetch fits too.
const fetch: FetchCallback = (input, init, { type }) =>
  globalThis.fetch(input, { ...init, signal: AbortSignal.timeout(type === 'statusList' ? 30_000 : 10_000) })

const fetchLimits: FetchLimits = {
  maxResponseBytes: 5 * 1024 * 1024,
  maxResponseBytesByType: { statusList: 16 * 1024 * 1024 },
}
```

The limit for a type is `maxResponseBytesByType[type]`, else `maxResponseBytes`, else the default of the package for the type, such as 16 MiB for a status list, else 10 MiB. A response with a larger `Content-Length` is rejected before its body is read, and a body stream is cancelled once it is larger, with an `IdentityCommonError`. Where fetch has no body stream, as in React Native without Expo, the body is read whole and checked afterwards. The fetch callback therefore does not have to limit the size itself.

`fetchWithLimits(options, { type, url, init, accept, defaultMaxResponseBytes })` returns a `Response` that holds the body in memory. `fetchAndParse` also parses the body of a response with a 2xx status with `parse`, e.g. with a zod schema or into a class instance. When `accept` is given, a response with a 2xx status of another media type is rejected with an `IdentityCommonError`, while a response with another status is returned without `data`, whatever its media type:

```typescript
import { fetchAndParse } from '@owf/identity-common'

const { response, data } = await fetchAndParse(
  { fetch, fetchLimits },
  { type: 'identifierList', url, accept: 'application/identifierlist+cwt', parse: (body) => IdentifierListCwt.fromToken(body) }
)
```

## Related Packages

This package is part of the Identity Common TypeScript project:

- [`@owf/jose`](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/jose) - JOSE/JWT implementation
- [`@owf/cose`](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/cose) - COSE/CWT implementation
- [`@owf/x509`](https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/x509) - X.509 certificate utilities

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).
