# @owf/eudi-tl

[![npm version](https://img.shields.io/npm/v/@owf/eudi-tl)](https://npmjs.com/package/@owf/eudi-tl)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

Parse and verify **ETSI TS 119 612** XML Trusted Lists (`TrustServiceStatusList`)
and expose normalized trust anchors.

It is the XML counterpart of [`@owf/eudi-lote`](https://www.npmjs.com/package/@owf/eudi-lote)
(ETSI TS 119 602, JSON): both formats resolve to the same normalized notion of a
trust anchor, so a verifier can consume either and, for example, derive AKIs
(SubjectKeyIdentifiers) to send to a wallet.

## Why

EUDI-context trust lists are published as **TS 119 602 (LoTE, JSON)**, but many
existing trust services are published as classic **TS 119 612 (XML)** — both the
standard eIDAS national lists (e.g. `TSLType/EUgeneric`, `TrstSvc/Svctype/*`,
`Svcstatus/*`) and other profiled lists. The parser and signature verification
are agnostic to the concrete URIs; profile-specific expectations are supplied by
the caller as a `ProfileRule`.

## Specification Reference

- [ETSI TS 119 612](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.03.01_60/ts_119612v020301p.pdf) - Trusted Lists

## Installation

```bash
npm install @owf/eudi-tl
# or
pnpm add @owf/eudi-tl
```

## Usage

### Loading a trusted list (verify, then parse)

```typescript
import {
  ACTIVE_SERVICE_STATUSES,
  loadTrustedList,
  getTrustAnchors,
} from '@owf/eudi-tl';

// Verify the list's XAdES signature, then parse it. Pins the scheme operator
// certificate(s) so a list signed by some other key fails closed.
const trustedList = await loadTrustedList(xml, {
  trustAnchors: [schemeOperatorCertDer],
});

// Flatten to individual anchors, keeping only active (granted) services.
const anchors = getTrustAnchors(trustedList, {
  serviceStatus: ACTIVE_SERVICE_STATUSES,
});

for (const anchor of anchors) {
  // anchor.certificate          — base64 DER, when the list embeds one
  // anchor.subjectKeyIdentifier — lowercase hex, for AKI queries
  // anchor.serviceTypeIdentifier / anchor.serviceStatus / anchor.providerName
}
```

### Following the EU hierarchy (LOTL → national lists)

The EU **List of Trusted Lists** is the root of the eIDAS hierarchy: it points
to every national list and publishes, for each one, the certificate(s) that list
is signed with. So only the LOTL's own signers have to be pinned — the anchors
of the national lists come from the LOTL itself:

```typescript
import {
  getEuLotlTrustAnchors,
  getPointerSigningCertificates,
  loadEuLotl,
  loadTrustedList,
} from '@owf/eudi-tl';

// Verified against the LOTL signing certificates shipped with this package.
const lotl = await loadEuLotl(lotlXml);

// The Spanish list's anchors, as published by the LOTL.
const anchors = getPointerSigningCertificates(lotl, { schemeTerritory: 'ES' });
const esList = await loadTrustedList(esXml, { trustAnchors: anchors });
```

`loadEuLotl` verifies the signature against `getEuLotlTrustAnchors()` and checks
the `TrustedListProfiles.euLotl` profile. Pass your own `trustAnchors` to
override the shipped set.

#### Why the LOTL signers are pinned, and how to update them

The shipped set (`EU_LOTL_SIGNING_CERTIFICATES`, with its
`EU_LOTL_ANCHORS_PROVENANCE`) is the one out-of-band anchor the hierarchy needs:
it cannot be bootstrapped from the LOTL itself, since a forged list would carry
a forged self-pointer. The European Commission publishes it in the Official
Journal, which the provenance record links.

Those certificates rotate, so a deployment can stay current without waiting for
a release of this package:

1. pass your own `trustAnchors`, e.g. from configuration;
2. read the currently published set from a verified LOTL's self-pointer and
   persist it — a rotation is always announced in a list that is still signed by
   the previous generation of keys:

   ```typescript
   const current = getPointerSigningCertificates(lotl, {
     tslType: TSLType.EUlistofthelists,
   });
   ```

3. if the pinned set has fallen behind entirely, follow the pivot LOTLs
   advertised in the list's `SchemeInformationURI`.

`scripts/refresh-lotl-anchors.mts` regenerates the shipped constant from the
live LOTL, verifying it against the currently pinned set first.

### Parsing without signature verification

`parseTrustedList` performs no signature check — use it for lists whose
authenticity is established elsewhere, or for inspection:

```typescript
import { parseTrustedList, validateTrustedList } from '@owf/eudi-tl';

const trustedList = parseTrustedList(xml);
const { valid, errors } = validateTrustedList(trustedList);
```

### Verifying the signature only

```typescript
import { verifyTrustedListSignature } from '@owf/eudi-tl';

const { signerCertificateBase64 } = await verifyTrustedListSignature(xml, {
  trustAnchors: [schemeOperatorCertDer], // optional but recommended
});
```

Without `trustAnchors`, only the cryptographic validity of the enveloped
signature is checked — that proves integrity, not trust. Production callers
should always pin the scheme operator certificate(s).

Verification uses the global Web Crypto API by default. To run it through a
reviewed or policy-constrained engine ("bring your own crypto"), pass a
`crypto` implementation:

```typescript
await verifyTrustedListSignature(xml, { crypto: myWebCrypto });
```

xadesjs exposes a single process-wide crypto engine, so this is applied by
(re)setting that global engine before verification, not as an isolated per-call
context.

### Validating against a profile

Profiled ecosystems constrain the `TSLType` and the service type / status URIs
a list may use. The engine stays profile-agnostic — supply the constraints as a
`ProfileRule`:

```typescript
import { validateTrustedListProfile } from '@owf/eudi-tl';

const result = validateTrustedListProfile(trustedList, {
  name: 'my-profile',
  tslType: 'https://example.org/lists/tsl-type',
  serviceTypes: ['https://example.org/service-type/issuance'],
  serviceStatuses: ['https://example.org/service-status/active'],
});
```

For common ecosystems, ready-made rules ship as `TrustedListProfiles` so you
don't have to hand-write the URIs:

```typescript
import { TrustedListProfiles, validateTrustedListProfile } from '@owf/eudi-tl';

// EU LOTL, generic eIDAS national list, or EU Age Verification.
validateTrustedListProfile(trustedList, TrustedListProfiles.ageVerification);
```

A profile is an allowlist (matched after the structural schema): the `TSLType`
must match and every service type / status must be permitted. That fits curated,
homogeneous lists (e.g. Age Verification) directly; `euGeneric` therefore permits
all standard ETSI statuses and qualified service types — including the
withdrawn/ceased entries national lists retain — rather than narrowing to active
CAs. Narrow further with your own `ProfileRule` when you need to.

## Error Handling

All failures throw a subclass of `TrustedListException`:

- `TrustedListParseException` — the XML is not a well-formed TS 119 612 list
- `TrustedListSignatureException` — the signature is missing, invalid, or not
  signed by a pinned trust anchor. Treat this as fail-closed.

When a failure wraps an underlying error (e.g. a crypto error during
verification), it is preserved on the exception's `cause`.

## Test Fixtures

The test suite uses two small synthetic lists generated by
`scripts/generate-test-fixtures.mts`: an unsigned list exercising the parser
and a signed sample (throwaway self-signed test certificates) exercising XAdES
verification. The suite only verifies signatures — it never signs.

## License

Apache-2.0
