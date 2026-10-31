# @owf/eudi-inspector

[![npm version](https://img.shields.io/npm/v/@owf/eudi-inspector)](https://npmjs.com/package/@owf/eudi-inspector)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

Parse EUDI documents and check each element against its specification, as a library and as the command line tool
`eudi-inspect`. It is what the [EUDI Inspector](https://openwallet-foundation-labs.github.io/identity-common-ts/) web pages run on.

| Format | Specification | Input |
| --- | --- | --- |
| Trusted list | ETSI TS 119 612 | XML |
| List of Trusted Entities | ETSI TS 119 602 | JSON or JWS |
| Registration certificate | ETSI TS 119 475 | JWS |
| Access certificate | ETSI TS 119 411-8 | PEM, base64, hex or DER |
| Token Status List | draft-ietf-oauth-status-list-16 | JWT |
| SD-JWT and SD-JWT VC | RFC 9901, draft-ietf-oauth-sd-jwt-vc | compact, with or without Key Binding JWT |
| mdoc | ISO/IEC 18013-5 | IssuerSigned or DeviceResponse, CBOR as bytes, hex or base64url |
| OpenID4VP request | OpenID4VP, ETSI TS 119 475 | checked for over-asking against the registration certificate |

Each finding has a severity, a code, a message, the requirement it comes from where known, and a path into the parsed
document, so it can be shown at the element it concerns.

## Command line

```bash
npx @owf/eudi-inspector --help
```

Or install it, which adds `eudi-inspect`:

```bash
npm install --global @owf/eudi-inspector
```

A document is a file, an http(s) URL, `-` for standard input, or the document itself. The format is recognised, or given
with `--format`:

```bash
# A national trusted list, with its signer checked against the certificates the EU LOTL has for it
eudi-inspect https://tl.bundesnetzagentur.de/TL-DE.xml --lotl

# An SD-JWT VC presentation, with the issuer's trust anchor and what the verifier expects
eudi-inspect presentation.txt --key issuing-ca.pem --nonce n-0S6 --aud https://verifier.example

# A registration certificate for the relying party of an access certificate
eudi-inspect registration.jwt --access-certificate access.pem

# The status at an index of a status list, as JSON
curl -s https://example.com/statuslists/1 | eudi-inspect - --index 42 --json

# An OpenID4VP request against the registration certificate in its verifier_info
eudi-inspect over-asking request.jwt
```

Keys and certificates are given as a file or as text: a JWK, a JWK Set, or PEM. A certificate given with `--key` is the
trust anchor the `x5c` chain of the header has to lead to. Without a key, the signature is verified with the `x5c` of the
header, which proves integrity only.

`--json` prints the result with the parsed document, bytes as hex. `--link` prints a link that opens the document in the
web page of its format, with the input after the `#`, which browsers do not send to the server.

The exit status is 0 without errors, 1 with errors or an invalid signature, and 2 when a document cannot be read.
`--strict` also fails on warnings and on signatures that could not be verified, e.g. for want of a key.

### Single executable

The command line tool can be built as a single executable of Node.js, which runs without Node.js installed:

```bash
pnpm --filter @owf/eudi-inspector build:binary
packages/eudi-inspector/dist-binary/eudi-inspect --help
```

This needs Node.js 25.7 or later, and makes an executable for the platform it runs on. Each release of the `@owf/eudi-*`
packages has one for Linux x64 attached, as `eudi-inspect-linux-x64` with its SHA-256 checksum, under the tag
`eudi-v<version>`:

```bash
sha256sum --check eudi-inspect-linux-x64.sha256
chmod +x eudi-inspect-linux-x64
./eudi-inspect-linux-x64 --help
```

The workflow `.github/workflows/inspector-binary.yml` builds it, and also keeps the one of every change on `main` as an
artifact of its run.

## Library

```typescript
import { inspect, report } from '@owf/eudi-inspector'

const inspection = inspect(document, { key: issuerCertificatePem, nonce: 'n-0S6' })
for (const finding of inspection.findings) {
  console.log(finding.severity, finding.code, finding.path.join('.'), finding.message)
}

// Verify the signatures, and get the result as plain data
const result = await report(inspection, globalThis.crypto)
console.log(result.valid, result.signatures)
```

`inspect` recognises the format. To parse a document as one format, use its function: `inspectTrustedList`,
`inspectLoTE`, `inspectRegistrationCertificate`, `inspectAccessCertificate`, `inspectStatusList`, `inspectSdJwt` or
`inspectMdoc`. `checkRequest` checks an OpenID4VP request for over-asking. Each throws `InspectionError` when the input
cannot be read as its format.

An `Inspection` holds the parsed document as `value`, the `findings`, the `checks` that ran, the `notes` on what was not
checked, and the `signatures` to verify. Signatures are verified separately, as that is asynchronous:

```typescript
for (const signature of inspection.signatures ?? []) {
  const { status, message } = await signature.verify(globalThis.crypto)
  // status is 'valid', 'invalid', or 'unverified' when it cannot be checked, e.g. for want of a key
}
```

The Web Crypto implementation is passed in, so the package does not use the global one. A trusted list is checked
against the EU List of Trusted Lists when `loadLotl` is given, a function that returns its XML, e.g. fetched from
`EU_LOTL_URL`.

## Platform Support

The library works in Node.js (>=20) and in browsers. It uses `TextEncoder`, `TextDecoder` and `CompressionStream`, and
the Web Crypto implementation it is given. The command line tool needs Node.js 20 or later, and is not for React
Native.

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).
