import { parseCertificate } from '@owf/crypto'
import { base64urlEncode } from '@owf/identity-common'
import type { SignedSchemaMeta, SignOptions } from './types'

/**
 * Sign a SchemaMeta object as a JWS
 *
 * Per TS11, the Catalogue of Attestations API returns SchemaMeta objects
 * wrapped in JWS-signed JWTs.
 *
 * @example Using a local key via @owf/crypto:
 * ```typescript
 * import { ES256 } from '@owf/crypto'
 * import { signSchemaMeta, schemaMeta, schemaURI } from '@owf/eudi-attestation-schema'
 *
 * const { privateKey } = await ES256.generateKeyPair()
 * const signer = await ES256.getSigner(privateKey)
 *
 * const meta = schemaMeta()
 *   .version('1.0.0')
 *   .rulebookURI('https://example.com/rulebook.md')
 *   .attestationLoS('iso_18045_basic')
 *   .bindingType('key')
 *   .addSchemaURI(schemaURI().format('dc+sd-jwt').uri('https://example.com/schema.json').build())
 *   .build()
 *
 * const signed = await signSchemaMeta({
 *   schemaMeta: meta,
 *   keyId: 'catalog-signer-2025',
 *   certificates: [pemCertificate],
 *   signer,
 * })
 * ```
 */
export async function signSchemaMeta(options: SignOptions): Promise<SignedSchemaMeta> {
  const { schemaMeta, keyId, algorithm = 'ES256', certificates, signer } = options

  const header: Record<string, unknown> = {
    alg: algorithm,
    typ: 'attestation-schema+jwt',
    kid: keyId,
    x5c: certificates.map(parseCertificate),
  }

  const iat = Math.floor(Date.now() / 1000)
  const jwtPayload = { ...schemaMeta, iat }

  const encodedHeader = base64urlEncode(JSON.stringify(header))
  const encodedPayload = base64urlEncode(JSON.stringify(jwtPayload))
  const signingInput = `${encodedHeader}.${encodedPayload}`

  const signature = await signer(signingInput)
  const jws = `${signingInput}.${signature}`

  return {
    jws,
    header: {
      alg: algorithm,
      typ: 'attestation-schema+jwt',
      kid: keyId,
      x5c: header.x5c as string[],
    },
    payload: schemaMeta,
    iat,
  }
}
