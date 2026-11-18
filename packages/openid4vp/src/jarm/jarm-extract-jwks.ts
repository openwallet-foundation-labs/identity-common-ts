import type { JwkSet } from '@owf/jose'

export function extractEncryptionJwkFromJwks(
  jwks: JwkSet,
  {
    kid,
    supportedAlgValues,
  }: {
    kid?: string
    supportedAlgValues?: string[]
  }
) {
  if (kid) {
    return jwks.keys.find((jwk) => jwk.kid === kid)
  }

  // A key that is meant for signatures is never encrypted to, not even when it is the only key
  const keys = jwks.keys.filter((key) => key.use !== 'sig')

  let algFiltered = keys.filter((key) => key.alg && supportedAlgValues?.includes(key.alg))
  if (algFiltered.length === 0) algFiltered = keys

  // Prefer a key that is explicitly meant for encryption over one whose use is not stated
  return algFiltered.find((key) => key.use === 'enc') ?? algFiltered[0]
}
