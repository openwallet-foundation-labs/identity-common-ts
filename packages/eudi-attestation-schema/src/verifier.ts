import { decodeJwt } from '@owf/identity-common'
import { SchemaMetaError } from './schema-meta-error'
import { zSchemaMeta } from './schemas'
import type { VerifiedSchemaMeta, VerifyOptions } from './types'

/**
 * Verify and decode a signed SchemaMeta JWS
 *
 * Decodes the JWS, verifies the signature using the provided verifier,
 * and validates the payload against the TS11 SchemaMeta schema.
 *
 * @example
 * ```typescript
 * import { ES256 } from '@owf/crypto'
 * import { verifySchemaMeta } from '@owf/eudi-attestation-schema'
 *
 * const verifier = await ES256.getVerifier(publicKey)
 * const { header, payload } = await verifySchemaMeta({
 *   jws: signedJws,
 *   verifier,
 * })
 * ```
 */
export async function verifySchemaMeta(options: VerifyOptions): Promise<VerifiedSchemaMeta> {
  const { jws, verifier } = options

  const { header, payload, signature } = decodeJwt<Record<string, unknown>, Record<string, unknown>>(jws)

  const [encodedHeader, encodedPayload] = jws.split('.')
  const signingInput = `${encodedHeader}.${encodedPayload}`

  const isValid = await verifier(signingInput, signature)
  if (!isValid) {
    throw new SchemaMetaError('Invalid signature')
  }

  const parsed = zSchemaMeta.safeParse(payload)
  if (!parsed.success) {
    const messages = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n')
    throw new SchemaMetaError(`Invalid SchemaMeta payload:\n${messages}`)
  }

  return {
    header: {
      alg: header.alg as string,
      typ: header.typ as string,
      kid: header.kid as string,
      x5c: header.x5c as string[],
    },
    payload: parsed.data,
    iat: parsed.data.iat || Math.floor(Date.now() / 1000),
  }
}
