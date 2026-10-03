import { nowInSeconds } from '@owf/identity-common'
import { decodeJwt } from './decode'
import type { Base64urlString, Signer, Verifier } from './types'
import { base64urlEncode, SDJWTException } from './utils'

export type JwtData<Header extends Record<string, unknown>, Payload extends Record<string, unknown>> = {
  header?: Header
  payload?: Payload
  signature?: Base64urlString
  encoded?: string
}

/**
 * Options for the JWT verifier
 */
export type VerifierOptions = {
  /**
   * current time in seconds since epoch
   */
  currentDate?: number

  /**
   * allowed skew for the current time in seconds. Positive value that will lower the iat and nbf checks, and increase the exp check.
   */
  skewSeconds?: number

  /**
   * required claim keys for the payload.
   * If the payload does not contain these keys, the verification will fail.
   */
  requiredClaimKeys?: string[]

  /**
   * Expected audience for the processed SD-JWT payload.
   */
  expectedAudience?: string | string[]

  /**
   * Expected issuer for the processed SD-JWT payload.
   */
  expectedIssuer?: string | string[]

  /**
   * Expected subject for the processed SD-JWT payload.
   */
  expectedSubject?: string | string[]

  /**
   * Maximum acceptable age of the JWT in seconds, measured from iat.
   */
  maxAgeSeconds?: number

  /**
   * Expected Verifiable Credential Type (vct) for SD-JWT VC payload.
   */
  expectedVct?: string | string[]

  /**
   * Allowed JOSE algorithms for issuer-signed JWTs. `none` is always rejected.
   */
  allowedIssuerAlgorithms?: string[]

  /**
   * nonce used to verify the key binding jwt to prevent replay attacks.
   */
  keyBindingNonce?: string

  /**
   * Expected audience for the Key Binding JWT.
   */
  expectedKeyBindingAudience?: string | string[]

  /**
   * Maximum acceptable age of the Key Binding JWT, in seconds.
   */
  keyBindingMaxAgeSeconds?: number

  /**
   * Internal option used by SD-JWT validation to defer claim checks until after
   * disclosures are processed.
   */
  skipJwtClaimValidation?: boolean

  /**
   * disable the verification of the status claim in the payload.
   *
   * @default false
   */
  disableStatusVerification?: boolean

  /**
   * any other custom options
   */
  [key: string]: unknown
}

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item) => typeof item === 'string')

const validateNumericDate = (payload: Record<string, unknown>, claim: 'iat' | 'nbf' | 'exp') => {
  const value = payload[claim]
  if (value === undefined) return undefined
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new SDJWTException(`Verify Error: JWT ${claim} must be a number`, undefined, 'INVALID_JWT_FORMAT')
  }
  return value
}

const getAudiences = (audience: unknown): string[] | undefined => {
  if (typeof audience === 'string') return [audience]
  if (isStringArray(audience)) return audience
  return undefined
}

const validateAudience = (payload: Record<string, unknown>, expectedAudience: string | string[] | undefined) => {
  if (expectedAudience === undefined) return

  const expectedAudiences = Array.isArray(expectedAudience) ? expectedAudience : [expectedAudience]
  const audiences = getAudiences(payload.aud)

  if (!audiences || !expectedAudiences.some((expected) => audiences.includes(expected))) {
    throw new SDJWTException('Verify Error: Invalid audience', undefined, 'INVALID_AUDIENCE')
  }
}

const validateIssuer = (payload: Record<string, unknown>, expectedIssuer: string | string[] | undefined) => {
  if (expectedIssuer === undefined) return

  const expectedIssuers = Array.isArray(expectedIssuer) ? expectedIssuer : [expectedIssuer]
  const iss = payload.iss

  if (typeof iss !== 'string' || !expectedIssuers.includes(iss)) {
    throw new SDJWTException('Verify Error: Invalid issuer', undefined, 'INVALID_ISSUER')
  }
}

const validateSubject = (payload: Record<string, unknown>, expectedSubject: string | string[] | undefined) => {
  if (expectedSubject === undefined) return

  const expectedSubjects = Array.isArray(expectedSubject) ? expectedSubject : [expectedSubject]
  const sub = payload.sub

  if (typeof sub !== 'string' || !expectedSubjects.includes(sub)) {
    throw new SDJWTException('Verify Error: Invalid subject', undefined, 'INVALID_SUBJECT')
  }
}

const validateVct = (payload: Record<string, unknown>, expectedVct: string | string[] | undefined) => {
  if (expectedVct === undefined) return

  const expectedVcts = Array.isArray(expectedVct) ? expectedVct : [expectedVct]
  const vct = payload.vct

  if (typeof vct !== 'string' || !expectedVcts.includes(vct)) {
    throw new SDJWTException('Verify Error: Invalid VCT', undefined, 'INVALID_VCT')
  }
}

const validateMaxAge = (
  iat: number | undefined,
  currentDate: number,
  skew: number,
  maxAgeSeconds: number | undefined
) => {
  if (maxAgeSeconds === undefined) return

  if (iat === undefined) {
    throw new SDJWTException('Verify Error: JWT iat claim is missing', undefined, 'MISSING_REQUIRED_CLAIMS')
  }

  if (iat + maxAgeSeconds + skew < currentDate) {
    throw new SDJWTException('Verify Error: JWT is too old', undefined, 'JWT_TOO_OLD')
  }
}

export const validateJwtPayload = (payload: Record<string, unknown> | undefined, options?: VerifierOptions) => {
  if (!payload) {
    throw new SDJWTException('Verify Error: JWT payload is missing', undefined, 'INVALID_SD_JWT')
  }

  const skew = options?.skewSeconds ? options.skewSeconds : 0
  const currentDate = options?.currentDate ?? nowInSeconds()
  const iat = validateNumericDate(payload, 'iat')
  const nbf = validateNumericDate(payload, 'nbf')
  const exp = validateNumericDate(payload, 'exp')

  if (iat !== undefined && iat - skew > currentDate) {
    throw new SDJWTException('Verify Error: JWT is not yet valid', undefined, 'JWT_NOT_YET_VALID')
  }

  if (nbf !== undefined && nbf - skew > currentDate) {
    throw new SDJWTException('Verify Error: JWT is not yet valid', undefined, 'JWT_NOT_YET_VALID')
  }

  if (exp !== undefined && exp + skew <= currentDate) {
    throw new SDJWTException('Verify Error: JWT is expired', undefined, 'JWT_EXPIRED')
  }

  validateMaxAge(iat, currentDate, skew, options?.maxAgeSeconds)
  validateAudience(payload, options?.expectedAudience)
  validateIssuer(payload, options?.expectedIssuer)
  validateSubject(payload, options?.expectedSubject)
  validateVct(payload, options?.expectedVct)
}

// This class is used to create and verify JWT
// Contains header, payload, and signature
export class Jwt<
  Header extends Record<string, unknown> = Record<string, unknown>,
  Payload extends Record<string, unknown> = Record<string, unknown>,
> {
  public header?: Header
  public payload?: Payload
  public signature?: Base64urlString
  private encoded?: string

  constructor(data?: JwtData<Header, Payload>) {
    this.header = data?.header
    this.payload = data?.payload
    this.signature = data?.signature
    this.encoded = data?.encoded
  }

  public static decodeJWT<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
  >(jwt: string): { header: Header; payload: Payload; signature: Base64urlString } {
    return decodeJwt(jwt)
  }

  public static fromEncode<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
  >(encodedJwt: string): Jwt<Header, Payload> {
    const { header, payload, signature } = Jwt.decodeJWT<Header, Payload>(encodedJwt)

    const jwt = new Jwt<Header, Payload>({
      header,
      payload,
      signature,
      encoded: encodedJwt,
    })

    return jwt
  }

  public setHeader(header: Header): Jwt<Header, Payload> {
    this.header = header
    this.encoded = undefined
    return this
  }

  public setPayload(payload: Payload): Jwt<Header, Payload> {
    this.payload = payload
    this.encoded = undefined
    return this
  }

  protected getUnsignedToken() {
    if (!this.header || !this.payload) {
      throw new SDJWTException('Serialize Error: Invalid JWT')
    }

    if (this.encoded) {
      const parts = this.encoded.split('.')
      if (parts.length !== 3) {
        throw new SDJWTException(`Invalid JWT format: ${this.encoded}`, undefined, 'INVALID_JWT_FORMAT')
      }
      const unsignedToken = parts.slice(0, 2).join('.')
      return unsignedToken
    }

    const header = base64urlEncode(JSON.stringify(this.header))
    const payload = base64urlEncode(JSON.stringify(this.payload))
    return `${header}.${payload}`
  }

  public async sign(signer: Signer) {
    if (!this.header || this.header.alg === 'none') {
      throw new SDJWTException('Sign Error: alg "none" is not allowed')
    }
    const data = this.getUnsignedToken()
    this.signature = await signer(data)

    return this.encodeJwt()
  }

  public encodeJwt(): string {
    if (this.encoded) {
      return this.encoded
    }

    if (!this.header || !this.payload || !this.signature) {
      throw new SDJWTException('Serialize Error: Invalid JWT')
    }

    const header = base64urlEncode(JSON.stringify(this.header))
    const payload = base64urlEncode(JSON.stringify(this.payload))
    const signature = this.signature
    const compact = `${header}.${payload}.${signature}`
    this.encoded = compact

    return compact
  }

  /**
   * Verify the JWT using the provided verifier function.
   * It checks the signature and validates the iat, nbf, and exp claims if they are present.
   * @param verifier
   * @param options - Options for verification, such as current date and skew seconds
   * @returns
   */
  public async verify<T>(verifier: Verifier<T>, options?: T & VerifierOptions) {
    const alg = this.header?.alg
    if (typeof alg !== 'string' || alg === 'none') {
      throw new SDJWTException('Verify Error: alg "none" is not allowed', undefined, 'INVALID_JWT_SIGNATURE')
    }
    if (options?.allowedIssuerAlgorithms && !options.allowedIssuerAlgorithms.includes(alg)) {
      throw new SDJWTException(`Verify Error: Disallowed alg ${alg}`, undefined, 'INVALID_JWT_SIGNATURE')
    }

    if (!options?.skipJwtClaimValidation) {
      validateJwtPayload(this.payload, options)
    }

    if (!this.signature) {
      throw new SDJWTException('Verify Error: no signature in JWT', undefined, 'INVALID_JWT_SIGNATURE')
    }
    const data = this.getUnsignedToken()

    const verified = await verifier(data, this.signature, options)
    if (!verified) {
      throw new SDJWTException('Verify Error: Invalid JWT Signature', undefined, 'INVALID_JWT_SIGNATURE')
    }
    return { payload: this.payload, header: this.header }
  }
}
