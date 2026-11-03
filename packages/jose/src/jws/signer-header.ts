import { JoseInvalidArgumentError } from '../error'
import { zJwkThumbprintComponents } from '../jwk/thumbprint'
import type { Jwk } from '../jwk/z-jwk'
import { type JwsSigner, type JwsSignerMethod, jwsHeaderFromSigner } from './signer'

const isSameList = (a: ReadonlyArray<string>, b: ReadonlyArray<string>): boolean =>
  a.length === b.length && a.every((value, index) => value === b[index])

/** Same key when the RFC 7638 thumbprint members match, or all members for key types RFC 7638 doesn't cover. */
const isSameKey = (a: Jwk, b: Jwk): boolean => {
  const componentsA = zJwkThumbprintComponents.safeParse(a)
  const componentsB = zJwkThumbprintComponents.safeParse(b)
  if (componentsA.success && componentsB.success) {
    return JSON.stringify(componentsA.data) === JSON.stringify(componentsB.data)
  }
  if (componentsA.success || componentsB.success) return false

  const membersOf = (jwk: Jwk) => Object.keys(jwk).filter((member) => jwk[member] !== undefined)
  const membersA = membersOf(a)
  return (
    membersA.length === membersOf(b).length &&
    membersA.every((member) => JSON.stringify(a[member]) === JSON.stringify(b[member]))
  )
}

/**
 * Rejects a header that contradicts the signer, or that also identifies a signer of another method, as
 * `jwsSignerFromHeader` would establish another signer from it. The header doesn't have to identify the signer.
 *
 * @throws JoseInvalidArgumentError if the header identifies another signer.
 */
export function assertHeaderIdentifiesSigner(
  header: { kid?: string; jwk?: Jwk; x5c?: ReadonlyArray<string>; trust_chain?: ReadonlyArray<string> },
  signer: JwsSigner,
  issuer: string | undefined
): void {
  const signerHeader: {
    kid?: string
    jwk?: Jwk
    x5c?: ReadonlyArray<string>
    trust_chain?: ReadonlyArray<string>
  } = jwsHeaderFromSigner(signer)

  if (header.kid !== undefined && signerHeader.kid !== undefined && header.kid !== signerHeader.kid) {
    throw new JoseInvalidArgumentError(
      `Unable to sign the JWS, the kid in the header is '${header.kid}', but the signer is identified by kid '${signerHeader.kid}'.`
    )
  }

  if (header.x5c !== undefined && signerHeader.x5c !== undefined && !isSameList(header.x5c, signerHeader.x5c)) {
    throw new JoseInvalidArgumentError(
      'Unable to sign the JWS, the x5c in the header is not the certificate chain of the signer.'
    )
  }

  if (
    header.trust_chain !== undefined &&
    signerHeader.trust_chain !== undefined &&
    !isSameList(header.trust_chain, signerHeader.trust_chain)
  ) {
    throw new JoseInvalidArgumentError(
      'Unable to sign the JWS, the trust_chain in the header is not the trust chain of the signer.'
    )
  }

  if (header.jwk !== undefined && signerHeader.jwk !== undefined && !isSameKey(header.jwk, signerHeader.jwk)) {
    throw new JoseInvalidArgumentError(
      'Unable to sign the JWS, the jwk in the header is not the public key of the signer.'
    )
  }

  // A custom signer is established out of band, so the header can identify it in any way
  if (signer.method === 'custom') return

  // A `kid` fragment identifies a did signer when `iss` is a DID, as `jwsSignerFromHeader` resolves it against `iss`
  const kidIdentifiesDid =
    header.kid?.startsWith('did:') === true ||
    (header.kid?.startsWith('#') === true && issuer?.startsWith('did:') === true)
  const identifiedMethods: Array<[parameter: string, method: JwsSignerMethod, present: boolean]> = [
    ['x5c', 'x5c', header.x5c !== undefined],
    ['trust_chain', 'federation', header.trust_chain !== undefined],
    ['kid', 'did', kidIdentifiesDid],
    ['jwk', 'jwk', header.jwk !== undefined],
  ]
  const otherMethod = identifiedMethods.find(([, method, present]) => present && method !== signer.method)
  if (otherMethod) {
    const [parameter, method] = otherMethod
    throw new JoseInvalidArgumentError(
      `Unable to sign the JWS, the '${parameter}' in the header identifies a signer with method '${method}', but the signer has method '${signer.method}'.`
    )
  }
}
