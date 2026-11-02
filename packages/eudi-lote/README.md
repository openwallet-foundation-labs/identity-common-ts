# @owf/eudi-lote

SDK for creating, signing, and managing Lists of Trusted Entities (LoTE) per **ETSI TS 119 602**.

## Overview

This SDK implements the ETSI TS 119 602 standard for LoTE documents, enabling:

- **Create and manage LoTE documents** with trusted entities and their services
- **Sign LoTE documents** with private keys or custom signers (HSM/KMS)
- **Validate LoTE documents** against ETSI TS 119 602 schema

> **Note**: This package currently supports **JWT encoding only**. CBOR and XML encodings are not yet supported.

## Specification Reference

- [ETSI TS 119 602](https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf) - Trusted Lists

## Supported Lists

`validateLoteProfile` is tested against these published lists:

| List | Profile | Mode |
| --- | --- | --- |
| [EU PID Providers](https://acceptance.trust.tech.ec.europa.eu/lists/eudiw/pid-providers.json) (EC acceptance) | `LoteProfile.EuPidProvidersList` | `strict` |
| [EU Wallet Providers](https://acceptance.trust.tech.ec.europa.eu/lists/eudiw/wallet-providers.json) (EC acceptance) | `LoteProfile.EuWalletProvidersList` | `strict` |
| [EU WRPAC Providers](https://acceptance.trust.tech.ec.europa.eu/lists/eudiw/wrpac-providers.json) (EC acceptance) | `LoteProfile.EuWrpacProvidersList` | `strict` |
| [EU Pub-EAA Providers](https://acceptance.trust.tech.ec.europa.eu/lists/eudiw/pub-eaa-providers.json) (EC acceptance) | `LoteProfile.EuPubEaaProvidersList` | `strict` |
| [German PID Providers](https://trustlists.eudihub.de/pid-provider.jwt) | `LoteProfile.EuPidProvidersList` | `compat`, `allowedTerritories: ['DE']` |
| [German Wallet Providers](https://trustlists-sandbox.eudihub.de/wallet-provider.jwt) (sandbox) | `LoteProfile.EuWalletProvidersList` | `compat`, `allowedTerritories: ['DE']` |
| [Norwegian PID Providers](https://tillitsliste.test.eidas2sandkasse.net/no_eidas2sandkasse_test_pid.jws) (sandbox) | `LoteProfile.EuPidProvidersList` | `compat`, `allowedTerritories: ['NO']` |
| [Norwegian Access Certificate Authorities](https://tillitsliste.test.eidas2sandkasse.net/no_eidas2sandkasse_test_aca.jws) (sandbox) | `LoteProfile.EuWrpacProvidersList` | `compat`, `allowedTerritories: ['NO']` |
| [Norwegian Wallet Providers](https://tillitsliste.test.eidas2sandkasse.net/no_eidas2sandkasse_test_wallet.jws) (sandbox) | `EUWalletProvidersList` | Not supported: its trusted entity has no `TrustedEntityServices`, which the JSON schema requires |

## Installation

```bash
npm install @owf/eudi-lote
# or
pnpm add @owf/eudi-lote
```

## Usage

### Creating a LoTE Document

```typescript
import {
  createLote,
  trustedEntity,
  service,
  addTrustedEntity,
} from '@owf/eudi-lote';

// Create the base LoTE document (only SchemeOperatorName is required)
let lote = createLote({
  SchemeOperatorName: [{ lang: 'en', value: 'Example Trust Operator' }],
  SchemeOperatorAddress: {
    SchemeOperatorPostalAddress: [
      {
        lang: 'en',
        StreetAddress: 'Main Street 1',
        Locality: 'Berlin',
        PostalCode: '10115',
        Country: 'DE',
      },
    ],
    SchemeOperatorElectronicAddress: [
      { lang: 'en', uriValue: 'mailto:trust@example.org' },
    ],
  },
  SchemeName: [{ lang: 'en', value: 'Gym Membership Issuers' }],
  SchemeTerritory: 'DE',
});

// Build a trusted entity using the fluent builder
const gymEntity = trustedEntity()
  .name('Mighty Fitness Center GmbH')
  .tradeName('Mighty Fitness')
  .postalAddress({
    StreetAddress: 'Gym Street 5',
    Locality: 'Fitville',
    PostalCode: '54321',
    Country: 'DE',
  })
  .email('contact@gym.example.com')
  .website('https://gym.example.com')
  .infoUri('https://gym.example.com/about')
  .addService(
    service()
      .name('Gym Membership Attestation Issuance')
      .type('https://example.org/service-type/gym-attestation-issuer')
      .status('https://example.org/status/granted')
      .addPublicKey({
        kty: 'EC',
        crv: 'P-256',
        x: '...',
        y: '...',
        kid: 'gym-issuer-key-1',
        use: 'sig',
        alg: 'ES256',
      })
      .addEndpoint(
        'https://example.org/service-type/gym-attestation-issuer',
        'https://issuer.gym.example.com',
      )
      .build(),
  )
  .build();

// Add the entity to the LoTE document
lote = addTrustedEntity(lote, gymEntity);
```

### Service with Multiple Identity Types

The SDK supports all digital identity types from ETSI TS 119 602:

```typescript
const svc = service()
  .name('Multi-Identity Service')
  .type('https://example.org/service-type/issuer')
  .status('https://example.org/status/granted')
  // X.509 certificates
  .addCertificate('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...')
  // X.509 subject names
  .addX509SubjectName('CN=Test CA, O=Test Org, C=DE')
  // X.509 Subject Key Identifiers
  .addX509Ski('base64encodedSKI==')
  // JWK public keys
  .addPublicKey({ kty: 'EC', crv: 'P-256', x: '...', y: '...' })
  // Other identifiers
  .addOtherId('urn:example:custom-id:12345')
  .build();
```

### Service History

Track historical changes to services:

```typescript
const svc = service()
  .name('Current Service Name')
  .addPublicKey({ kty: 'EC', crv: 'P-256', x: '...', y: '...' })
  .addHistoryEntry({
    ServiceName: [{ lang: 'en', value: 'Previous Service Name' }],
    ServiceDigitalIdentity: { PublicKeyValues: [{ kty: 'EC', crv: 'P-256' }] },
    ServiceStatus: 'https://example.org/status/revoked',
    StatusStartingTime: '2023-01-01T00:00:00.000Z',
  })
  .build();
```

### Pointers to Other LoTE Lists

Reference other LoTE documents:

```typescript
const lote = createLote({
  SchemeOperatorName: [{ lang: 'en', value: 'Master Registry' }],
  PointersToOtherLoTE: [
    {
      LoTELocation: 'https://other-registry.example.com/lote',
      ServiceDigitalIdentities: [
        { PublicKeyValues: [{ kty: 'EC', crv: 'P-256', x: '...', y: '...' }] },
      ],
      LoTEQualifiers: [
        {
          LoTEType: 'https://example.org/lote-type/regional',
          SchemeOperatorName: [{ lang: 'en', value: 'Regional Operator' }],
          MimeType: 'application/jwt',
        },
      ],
    },
  ],
});
```

### Signing a LoTE Document

```typescript
import { signLote } from '@owf/eudi-lote';
import { ES256 } from '@owf/crypto';

// With a local key
const signer = await ES256.getSigner(privateKeyPem);
const signed = await signLote({
  lote,
  keyId: 'lote-signer-2025',
  signer,
});

console.log(signed.jws); // The signed JWS
```

### Using a KMS/HSM Signer

```typescript
const signed = await signLote({
  lote,
  keyId: 'lote-signer-2025',
  signer: async (data) => {
    return await myKmsService.sign('ES256', data);
  },
});
```

### Validating a LoTE Document

```typescript
import {
  validateLote,
  assertValidLote,
} from '@owf/eudi-lote';

// Get the validation result with all issues
const result = validateLote(lote);
for (const issue of result.issues) {
  // e.g. error invalid_format LoTE.ListAndSchemeInformation.DistributionPoints.0: Invalid URL
  console.log(issue.severity, issue.code, `${issue.path.join('.')}: ${issue.message}`);
}

// Or throw on invalid
assertValidLote(lote); // throws LoteValidationError if invalid
```

### Updating a LoTE Document

```typescript
import {
  updateLoteVersion,
  addTrustedEntity,
  removeTrustedEntity,
} from '@owf/eudi-lote';

// Increment version and update timestamps
let updatedList = updateLoteVersion(lote);

// Add new entity
updatedList = addTrustedEntity(updatedList, newEntity);

// Remove an entity by name
updatedList = removeTrustedEntity(updatedList, 'Old Gym Name');
```

## API Reference

### Signing

#### `signLote(options): Promise<SignedLote>`

Signs a LoTE document using the provided signer function.

#### `createLote(schemeInfo, entities?): LoteDocument`

Creates a new LoTE document with the given scheme information. Only `SchemeOperatorName` is required per ETSI TS 119 602.

#### `updateLoteVersion(lote): LoteDocument`

Increments the sequence number and updates timestamps.

#### `addTrustedEntity(lote, entity): LoteDocument`

Adds a trusted entity to the list.

#### `removeTrustedEntity(lote, entityName): LoteDocument`

Removes an entity by name.

### Validation

#### `validateLote(lote, { mode? }): ValidationResult`

Validates a LoTE document against the ETSI TS 119 602 v1.1.1 JSON schema. Returns `{ valid, issues }`, where each issue has a `severity`, a `code`, a `path` into the document and a `message`. Schema issues have a code of `SCHEMA_VALIDATION_CODES` from `@owf/identity-common`, such as `missing` or `invalid_value`, and the profile checks one of `LOTE_VALIDATION_CODES`. With `mode: 'compat'`, it also accepts a `LoTELegalNotice` that is an array of localized URIs, and `PolicyOrLegalNotice` items that have both keys.

When valid, the result has the document as `lote`: a `LoteDocument`, or a `CompatLoteDocument` in compat mode. A `CompatLoteDocument` is not a `LoteDocument`, as its `LoTELegalNotice` can be an array.

```typescript
const result = validateLote(lote, { mode: 'compat' });
if (result.valid) {
  result.lote; // CompatLoteDocument
}
```

The rules of the EU lists (2-letter country codes, non-empty names, at least one digital identity, X.509 certificate encoding, and so on) are not part of the JSON schema: `validateLoteProfile` applies them. The known differences from the JSON schema are listed in [`src/__tests__/schema-drift.test.mts`](./src/__tests__/schema-drift.test.mts).

#### `assertValidLote(lote, { mode? }): asserts lote is LoteDocument`

Type assertion that throws `LoteValidationError`, a `LoteError` with the `issues` of `validateLote`, if the LoTE document is invalid. In compat mode it asserts a `CompatLoteDocument`.

#### `validateLoteProfile(lote, profile: LoteProfile | LoteProfile[], options?): ValidationResult`

Validates a LoTE document against a known LoTE Profile, such as EU PID Providers List, mDL Providers List, etc. Returns `{ valid, issues }` like `validateLote`. A document whose `LoTEType` matches none of the profiles gets an `unexpected_lote_type` issue for each profile.

When valid, the result has the LoTEType of the profile the document matches as `loteType`, and the document as `lote`, typed as the `LoteProfileDocument` of that profile: its `LoTEType`, `ServiceTypeIdentifier` and `ServiceStatus` are the values the profile allows. Check `valid` and then `loteType` to narrow `lote` to one profile.

```typescript
const result = validateLoteProfile(lote, [LoteProfile.EuPidProvidersList, LoteProfile.EuPubEaaProvidersList]);
if (result.valid && result.loteType === LOTE_TYPES.EuPubEaaProvidersList) {
  result.lote; // LoteProfileDocument<LoteProfile.EuPubEaaProvidersList>
}
```

Options:

- `mode`: `strict` (default) validates the list exactly as the profile defines it. `compat` also accepts deviations of lists in use that don't change who is trusted. The table below lists them.
- `allowedTerritories`: compat mode only. The accepted `SchemeTerritory` values, `['EU']` by default. Pass the territory of a national list of an EU type, such as `['DE']`. In strict mode the territory must be `EU` (TS 119 602 D to I), and passing `allowedTerritories` throws a `LoteError`.

| What | Profile(s) | Notes |
| --- | --- | --- |
| A `LoTELegalNotice` that is an array of localized URIs | All, and `validateLote` | The German EUDI Wallet sandbox lists |
| A `PolicyOrLegalNotice` item with both `LoTEPolicy` and `LoTELegalNotice` | All, and `validateLote` | The German EUDI Wallet sandbox lists |
| A `ServiceStatus` of `http://uri.etsi.org/19602/PidProvidersList/SvcStatus/notified`, with an optional `StatusStartingTime` | EU PID Providers List | No profile defines this status. The German PID Providers List sets it |
| A `SchemeTerritory` other than `EU` | All | Only the values passed in `allowedTerritories`, such as `['DE']` |

A Pub-EAA Providers List gives every service a `ServiceStatus` (TS 119 602 H), and a withdrawn provider stays listed with `http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn`. The list is still valid: only trust services with `http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified`. The valid result of a Pub-EAA Providers List has the trusted entities with only their notified services as `notifiedTrustedEntities`.

```typescript
// The German EUDI Wallet PID Providers List
validateLoteProfile(lote, LoteProfile.EuPidProvidersList, { mode: 'compat', allowedTerritories: ['DE'] });
```

#### `getNotifiedTrustedEntities(lote): TrustedEntity[]`

Returns the trusted entities of a list validated with `validateLoteProfile`, with only their notified services. It leaves out withdrawn services, and entities with no notified service left. A service without a `ServiceStatus` is notified, as in the profiles that don't define one.

```typescript
const result = validateLoteProfile(lote, LoteProfile.EuPubEaaProvidersList);
if (result.valid) {
  const trustedEntities = getNotifiedTrustedEntities(result.lote);
}
```

### Builders

#### `trustedEntity(): TrustedEntityBuilder`

Fluent builder for creating trusted entities.

Methods:

- `.name(name, lang?)` - Entity name
- `.tradeName(name, lang?)` - Trade name
- `.registrationId(id, lang?)` - Registration identifier
- `.postalAddress(address, lang?)` - Postal address
- `.email(email, lang?)` - Email address
- `.website(url, lang?)` - Website URL
- `.infoUri(uri, lang?)` - Information URI
- `.addExtension(extension)` - Add an extension
- `.addService(service)` - Add a service
- `.build()` - Build the entity, checked against the JSON schema rules (use `validateLoteProfile` on the list for the EU rules)

#### `service(): ServiceBuilder`

Fluent builder for creating services.

Methods:

- `.name(name, lang?)` - Service name
- `.type(typeUri)` - Service type identifier
- `.status(statusUri)` - Service status
- `.statusStartingTime(isoTimestamp)` - When status became effective
- `.addCertificate(base64Cert)` - Add X.509 certificate
- `.addX509SubjectName(subjectName)` - Add X.509 subject name
- `.addX509Ski(base64SKI)` - Add X.509 Subject Key Identifier
- `.addPublicKey(jwk)` - Add JWK public key
- `.addOtherId(identifier)` - Add custom identifier
- `.addEndpoint(uri)` or `.addEndpoint(type, uri)` - Add service endpoint, with an optional `ServiceType`
- `.addExtension(extension)` - Add service extension
- `.addHistoryEntry(entry)` - Add service history entry
- `.build()` - Build the service, checked against the JSON schema rules

## Types

See [src/types.ts](./src/types.ts) for complete type definitions including:

- `LoteDocument` - Root LoTE document structure
- `TrustedEntity` - Entity in the LoTE document
- `Service` - Service provided by an entity
- `ServiceDigitalIdentity` - Digital identity for a service
- `ServiceHistory` / `ServiceHistoryInstance` - Historical service states
- `PointersToOtherLoTE` / `OtherLotePointer` - Cross-list references
- `ValidationResult` / `LoteValidationIssue` - Validation types

All document types are derived from Zod schemas. You can import and use the schemas
directly for custom validation or to build upon:

```typescript
import { zLoteDocument, zTrustedEntity } from '@owf/eudi-lote';

// Use schemas for custom validation
const result = zLoteDocument.safeParse(data);

// Compose with your own schemas
const zMyTrustedEntity = zTrustedEntity.extend({ customField: z.string() });
```

### SignerFunction

```typescript
type SignerFunction = (data: Uint8Array) => Promise<Uint8Array | string>;
```

## External Key Management

The SDK supports delegating signing to external services:

### Azure Key Vault

```typescript
import { CryptographyClient } from '@azure/keyvault-keys';

const signed = await signLote({
  lote,
  keyId: 'lote-signer',
  signer: async (data) => {
    const result = await cryptoClient.sign('ES256', data);
    return result.result;
  },
});
```

### AWS KMS

```typescript
import { KMSClient, SignCommand } from '@aws-sdk/client-kms';

const signed = await signLote({
  lote,
  keyId: 'lote-signer',
  signer: async (data) => {
    const response = await kmsClient.send(
      new SignCommand({
        KeyId: 'alias/lote-signer',
        Message: data,
        MessageType: 'RAW',
        SigningAlgorithm: 'ECDSA_SHA_256',
      }),
    );
    return new Uint8Array(response.Signature!);
  },
});
```

## Security Considerations

- **Protect signing keys** - Use HSM or KMS for production
- **Validate trust anchors** - Verify the signer's certificate chain
- **Check sequence numbers** - Ensure you have the latest version
- **Use HTTPS** - Always use HTTPS for distribution points
- **Validate before signing** - Use `assertValidLote` before signing

## License

Apache-2.0
