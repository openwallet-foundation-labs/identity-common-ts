import { parseWithErrorHandling } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { zCredentialIssuerMetadataWithDraftVersion } from '../../metadata/credential-issuer/z-credential-issuer-metadata'
import { findyProvicisCredentialIssuerMetadataJson } from './findy-provicis-credential-issuer-metadata-json'

describe('Interoperability | Provicis', () => {
  test('should correctly parse and validate credential issuer metadata', () => {
    // NOTE: the metadata uses `null` where it's not allowed. Keeping the test here with failing for now, we should
    // update this once the metadata has been updated.
    expect(() =>
      parseWithErrorHandling(zCredentialIssuerMetadataWithDraftVersion, findyProvicisCredentialIssuerMetadataJson)
    ).toThrow(
      expect.objectContaining({
        issues: [
          expect.objectContaining({
            code: 'invalid_value',
            context: {
              branches: [
                [
                  expect.objectContaining({
                    code: 'invalid_type',
                    path: [
                      'credential_configurations_supported',
                      'https://alennusperuste.todiste.fi/credentials/v1/PensionCredential',
                      'proof_types_supported',
                      'jwt',
                      'key_attestations_required',
                    ],
                  }),
                ],
                [expect.objectContaining({ code: 'missing_value', path: ['credentials_supported'] })],
              ],
              labels: ['OpenID4VCI 1.0 or drafts 13 to 15', 'OpenID4VCI draft 11'],
            },
          }),
        ],
      })
    )
  })
})
