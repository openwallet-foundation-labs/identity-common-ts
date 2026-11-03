import { getSdAlgAndPayload } from './decode'
import { FlattenJson } from './flattenJson'
import { GeneralJson } from './generalJson'
import { Jwt, type VerifierOptions, validateJwtPayload } from './jwt'
import { KbJwt } from './kbjwt'
import { pack, SdJwt } from './sdjwt'
import {
  DEFAULT_SECURE_HASH_ALGORITHMS,
  type DisclosureFrame,
  type Hasher,
  IANA_HASH_ALGORITHMS,
  KB_JWT_TYP,
  type KbOptions,
  type PresentationFrame,
  type SafeVerifyResult,
  SD_DECOY,
  SD_DIGEST,
  SD_LIST_KEY,
  type SdJwtCompact,
  type SdJwtConfig,
  type Signer,
  type VerificationError,
  type VerificationErrorCode,
} from './types'
import { base64urlEncode, ensureError, SdJwtError, uint8ArrayToBase64Url } from './utils'
import { decodeBase64urlJsonStrict } from './utils/strict-json'

export * from './decode'
export * from './decoy'
export * from './flattenJson'
export * from './generalJson'
export * from './jwt'
export * from './kbjwt'
export * from './present'
export * from './sdjwt'
// Re-export all types, utils, decode, and present functionality
export * from './types'
export * from './utils'

export type SdJwtPayload = Record<string, unknown>

/**
 * Internal utility function to validate that a payload does not contain reserved field names.
 */
function validateReservedFieldsInternal(payload: Record<string, unknown>): void {
  const reservedFields = new Set([SD_DIGEST, '_sd_alg', SD_DECOY, SD_LIST_KEY])

  const visit = (node: unknown) => {
    if (!node || typeof node !== 'object') {
      return
    }

    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (reservedFields.has(key)) {
        throw new SdJwtError(`Reserved field name "${key}" is not allowed`)
      }
      visit(value)
    }
  }

  visit(payload)
}

export class SdJwtInstance<ExtendedPayload extends SdJwtPayload, T = unknown> {
  //header type
  protected type?: string

  public static readonly defaultHashAlg = 'sha-256'

  protected userConfig: SdJwtConfig<T> = {}

  constructor(userConfig?: SdJwtConfig<T>) {
    if (userConfig) {
      if (userConfig.hashAlg && !IANA_HASH_ALGORITHMS.includes(userConfig.hashAlg)) {
        throw new SdJwtError(`Invalid hash algorithm: ${userConfig.hashAlg}`)
      }
      const allowedDisclosureHashAlgorithms =
        userConfig.allowedDisclosureHashAlgorithms ?? DEFAULT_SECURE_HASH_ALGORITHMS
      if (userConfig.hashAlg && !allowedDisclosureHashAlgorithms.includes(userConfig.hashAlg)) {
        throw new SdJwtError(`Disallowed hash algorithm: ${userConfig.hashAlg}`)
      }
      this.userConfig = userConfig
    }
  }

  private async createKbJwt(options: KbOptions, sdHash: string): Promise<KbJwt> {
    if (!this.userConfig.kbSigner) {
      throw new SdJwtError('Key Binding Signer not found')
    }
    if (!this.userConfig.kbSignAlg) {
      throw new SdJwtError('Key Binding sign algorithm not specified')
    }

    const { payload } = options
    const kbJwt = new KbJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: this.userConfig.kbSignAlg,
      },
      payload: { ...payload, sd_hash: sdHash },
    })

    await kbJwt.sign(this.userConfig.kbSigner)
    return kbJwt
  }

  private async SignJwt(jwt: Jwt) {
    if (!this.userConfig.signer) {
      throw new SdJwtError('Signer not found')
    }
    await jwt.sign(this.userConfig.signer)
    return jwt
  }

  private async VerifyJwt(jwt: Jwt, options?: T & VerifierOptions) {
    if (!this.userConfig.verifier) {
      throw new SdJwtError('Verifier not found', { code: 'VERIFIER_NOT_FOUND' })
    }
    return jwt.verify<T>(this.userConfig.verifier, options)
  }

  public async issue<Payload extends ExtendedPayload>(
    payload: Payload,
    disclosureFrame?: DisclosureFrame<Payload>,
    options?: {
      header?: object // This is for customizing the header of the jwt
    }
  ): Promise<SdJwtCompact> {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }

    if (!this.userConfig.saltGenerator) {
      throw new SdJwtError('SaltGenerator not found')
    }

    if (!this.userConfig.signAlg) {
      throw new SdJwtError('sign alogrithm not specified')
    }
    if (this.userConfig.signAlg === 'none') {
      throw new SdJwtError('sign algorithm "none" is not allowed')
    }

    this.validateReservedFields<Payload>(payload)
    this.validateDisclosureFrame<Payload>(disclosureFrame)

    const hasher = this.userConfig.hasher
    const hashAlg = this.userConfig.hashAlg ?? SdJwtInstance.defaultHashAlg
    const allowedDisclosureHashAlgorithms =
      this.userConfig.allowedDisclosureHashAlgorithms ?? DEFAULT_SECURE_HASH_ALGORITHMS
    if (!allowedDisclosureHashAlgorithms.includes(hashAlg)) {
      throw new SdJwtError(`Disallowed hash algorithm: ${hashAlg}`)
    }

    const { packedClaims, disclosures } = await pack(
      payload,
      disclosureFrame,
      { hasher, alg: hashAlg },
      this.userConfig.saltGenerator
    )
    const alg = this.userConfig.signAlg
    const OptionHeader = options?.header ?? {}
    const CustomHeader = this.userConfig.omitTyp ? OptionHeader : { typ: this.type, ...OptionHeader }
    const header = { ...CustomHeader, alg }
    const jwt = new Jwt({
      header,
      payload: {
        ...packedClaims,
        _sd_alg: disclosureFrame ? hashAlg : undefined,
      },
    })
    await this.SignJwt(jwt)

    const sdJwt = new SdJwt({
      jwt,
      disclosures,
    })

    return sdJwt.encodeSdJwt()
  }

  /**
   * Validates if the payload contains any reserved claim names. If so it will throw an error.
   * @param payload
   * @returns
   */
  protected validateReservedFields<T extends ExtendedPayload>(payload: T) {
    validateReservedFieldsInternal(payload as Record<string, unknown>)
  }

  protected validateDisclosureFrame<T extends ExtendedPayload>(_disclosureFrame?: DisclosureFrame<T>) {
    return
  }

  public async present<T extends Record<string, unknown>>(
    encodedSdJwt: string,
    presentationFrame?: PresentationFrame<T>,
    options?: {
      kb?: KbOptions
    }
  ): Promise<SdJwtCompact> {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }
    const hasher = this.userConfig.hasher

    const sdjwt = await SdJwt.fromEncode(encodedSdJwt, hasher)
    if (sdjwt.kbJwt) {
      throw new SdJwtError('Holder cannot present an SD-JWT with KB-JWT')
    }

    if (!sdjwt.jwt?.payload) throw new SdJwtError('Payload not found')
    const presentSdJwtWithoutKb = await sdjwt.present(presentationFrame, hasher)

    if (!options?.kb) {
      return presentSdJwtWithoutKb
    }

    const sdHashStr = await this.calculateSdHash(presentSdJwtWithoutKb, sdjwt, hasher)

    sdjwt.kbJwt = await this.createKbJwt(options.kb, sdHashStr)
    return sdjwt.present(presentationFrame, hasher)
  }

  // This function is for verifying the SD JWT
  // If requiredClaimKeys is provided, it will check if the required claim keys are presentation in the SD JWT
  // If requireKeyBindings is true, it will check if the key binding JWT is presentation and verify it
  public async verify(encodedSdJwt: string, options?: T & VerifierOptions) {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }
    const hasher = this.userConfig.hasher

    const sdjwt = await SdJwt.fromEncode(encodedSdJwt, hasher)
    if (!sdjwt.jwt?.payload) {
      throw new SdJwtError('Invalid SD JWT')
    }
    const { payload, header } = await this.validate(encodedSdJwt, options)

    if (options?.requiredClaimKeys) {
      const keys = await sdjwt.keys(hasher)
      const missingKeys = options.requiredClaimKeys.filter((k) => !keys.includes(k))
      if (missingKeys.length > 0) {
        throw new SdJwtError(`Missing required claim keys: ${missingKeys.join(', ')}`)
      }
    }

    if (!options?.keyBindingNonce) {
      return { payload, header }
    }

    if (!sdjwt.kbJwt) {
      throw new SdJwtError('Key Binding JWT not exist')
    }
    if (!this.userConfig.kbVerifier) {
      throw new SdJwtError('Key Binding Verifier not found')
    }
    const kb = await sdjwt.kbJwt.verifyKb({
      verifier: this.userConfig.kbVerifier,
      payload,
      nonce: options.keyBindingNonce,
      options,
    })
    if (!kb) {
      throw new Error('signature is not valid')
    }

    const sdHashfromKb = kb.payload.sd_hash
    const sdjwtWithoutKb = new SdJwt({
      jwt: sdjwt.jwt,
      disclosures: sdjwt.disclosures,
    })

    const presentSdJwtWithoutKb = sdjwtWithoutKb.encodeSdJwt()
    const sdHashStr = await this.calculateSdHash(presentSdJwtWithoutKb, sdjwt, hasher)

    if (sdHashStr !== sdHashfromKb) {
      throw new SdJwtError('Invalid sd_hash in Key Binding JWT')
    }

    return { payload, header, kb }
  }

  /**
   * Safe verification that collects all errors instead of failing fast.
   * Returns a result object with either the verified data or an array of all errors.
   *
   * @param encodedSdJwt - The encoded SD-JWT to verify
   * @param options - Verification options
   * @returns A SafeVerifyResult containing either success data or collected errors
   */
  public async safeVerify(
    encodedSdJwt: string,
    options?: T & VerifierOptions
  ): Promise<
    SafeVerifyResult<{
      payload: ExtendedPayload
      header: Record<string, unknown> | undefined
      kb?: {
        payload: Record<string, unknown>
        header: Record<string, unknown>
      }
    }>
  > {
    const errors: VerificationError[] = []

    // Helper to add errors
    const addError = (code: VerificationErrorCode, message: string, details?: unknown) => {
      errors.push({ code, message, details })
    }

    // Helper to convert exception to error code. The code is set where the error is thrown, so it
    // does not depend on the (human-readable) error message.
    const exceptionToCode = (error: Error): VerificationErrorCode =>
      error instanceof SdJwtError && error.code ? error.code : 'UNKNOWN_ERROR'

    // Check basic configuration first
    if (!this.userConfig.hasher) {
      addError('HASHER_NOT_FOUND', 'Hasher not found')
    }
    if (!this.userConfig.verifier) {
      addError('VERIFIER_NOT_FOUND', 'Verifier not found')
    }

    // If basic config is missing, return early
    if (errors.length > 0) {
      return { success: false, errors }
    }

    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }

    // hasher and verifier are guaranteed to be defined here
    const hasher = this.userConfig.hasher

    // Try to decode and validate the SD-JWT
    let sdjwt: SdJwt | undefined
    let payload: ExtendedPayload | undefined
    let header: Record<string, unknown> | undefined

    try {
      sdjwt = await SdJwt.fromEncode(encodedSdJwt, hasher)
      if (!sdjwt.jwt?.payload) {
        addError('INVALID_SD_JWT', 'Invalid SD JWT: missing JWT or payload')
      }
    } catch (e) {
      const error = ensureError(e)
      addError('INVALID_SD_JWT', `Failed to decode SD-JWT: ${error.message}`, error)
    }

    // Validate signature and claims
    if (sdjwt?.jwt) {
      try {
        const result = await this.VerifyJwt(sdjwt.jwt, {
          ...options,
          skipJwtClaimValidation: true,
        } as T & VerifierOptions)
        header = result.header
        const claims = await sdjwt.getClaims(hasher)
        payload = claims as ExtendedPayload
        validateJwtPayload(payload, options)
      } catch (e) {
        const error = ensureError(e)
        const code = exceptionToCode(error)
        addError(code, error.message, error)
      }
    }

    // Check required claim keys
    if (sdjwt && options?.requiredClaimKeys) {
      try {
        const keys = await sdjwt.keys(hasher)
        const missingKeys = options.requiredClaimKeys.filter((k) => !keys.includes(k))
        if (missingKeys.length > 0) {
          addError('MISSING_REQUIRED_CLAIMS', `Missing required claim keys: ${missingKeys.join(', ')}`, { missingKeys })
        }
      } catch (e) {
        const error = ensureError(e)
        addError('UNKNOWN_ERROR', `Failed to check required claims: ${error.message}`, error)
      }
    }

    // Verify key binding if requested
    let kb: { payload: Record<string, unknown>; header: Record<string, unknown> } | undefined
    if (options?.keyBindingNonce && sdjwt) {
      if (!sdjwt.kbJwt) {
        addError('KEY_BINDING_JWT_MISSING', 'Key Binding JWT not exist')
      } else if (!this.userConfig.kbVerifier) {
        addError('KEY_BINDING_VERIFIER_NOT_FOUND', 'Key Binding Verifier not found')
      } else if (payload) {
        try {
          const kbResult = await sdjwt.kbJwt.verifyKb({
            verifier: this.userConfig.kbVerifier,
            payload,
            nonce: options.keyBindingNonce,
            options,
          })
          if (!kbResult) {
            addError('KEY_BINDING_SIGNATURE_INVALID', 'Key binding signature is not valid')
          } else {
            kb = kbResult

            // Verify sd_hash
            const sdjwtWithoutKb = new SdJwt({
              jwt: sdjwt.jwt,
              disclosures: sdjwt.disclosures,
            })
            const presentSdJwtWithoutKb = sdjwtWithoutKb.encodeSdJwt()
            const sdHashStr = await this.calculateSdHash(presentSdJwtWithoutKb, sdjwt, hasher)

            if (sdHashStr !== kbResult.payload.sd_hash) {
              addError('KEY_BINDING_SD_HASH_INVALID', 'Invalid sd_hash in Key Binding JWT', {
                expected: sdHashStr,
                received: kbResult.payload.sd_hash,
              })
            }
          }
        } catch (e) {
          const error = ensureError(e)
          // Time checks (iat, nbf, exp, maximum age) carry their own KEY_BINDING_JWT_* code; any other
          // failure is reported as an invalid key binding.
          const code = error instanceof SdJwtError && error.code ? error.code : 'KEY_BINDING_SIGNATURE_INVALID'
          addError(code, `Key binding verification failed: ${error.message}`, error)
        }
      }
    }

    // Return result
    if (errors.length > 0) {
      return { success: false, errors }
    }

    return {
      success: true,
      data: {
        payload: payload as ExtendedPayload,
        header,
        kb,
      },
    }
  }

  private async calculateSdHash(presentSdJwtWithoutKb: string, sdjwt: SdJwt, hasher: Hasher) {
    if (!sdjwt.jwt?.payload) {
      throw new SdJwtError('Invalid SD JWT')
    }
    const { _sd_alg } = getSdAlgAndPayload(sdjwt.jwt.payload)
    const sdHash = await hasher(presentSdJwtWithoutKb, _sd_alg)
    const sdHashStr = uint8ArrayToBase64Url(sdHash)
    return sdHashStr
  }

  /**
   * This function is for validating the SD JWT
   * Checking signature, if provided the iat and exp when provided and return its the claims
   * @param encodedSdJwt
   * @param options
   * @returns
   */
  public async validate(encodedSdJwt: string, options?: T & VerifierOptions) {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }
    const hasher = this.userConfig.hasher

    const sdjwt = await SdJwt.fromEncode(encodedSdJwt, hasher)
    if (!sdjwt.jwt) {
      throw new SdJwtError('Invalid SD JWT')
    }

    const verifiedPayloads = await this.VerifyJwt(sdjwt.jwt, {
      ...options,
      skipJwtClaimValidation: true,
    } as T & VerifierOptions)
    const claims = await sdjwt.getClaims<ExtendedPayload>(hasher)
    // Validate that unpacked claims do not contain reserved field names
    validateReservedFieldsInternal(claims)
    validateJwtPayload(claims, options)
    return { payload: claims, header: verifiedPayloads.header }
  }

  public config(newConfig: SdJwtConfig<T>) {
    this.userConfig = { ...this.userConfig, ...newConfig }
  }

  public encode(sdJwt: SdJwt): SdJwtCompact {
    return sdJwt.encodeSdJwt()
  }

  public decode<Header extends Record<string, unknown> = Record<string, unknown>>(encodedSdJwt: SdJwtCompact) {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }
    return SdJwt.fromEncode<Header, ExtendedPayload>(encodedSdJwt, this.userConfig.hasher)
  }

  public async keys(encodedSdJwt: SdJwtCompact) {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }
    const sdjwt = await SdJwt.fromEncode<Record<string, unknown>, ExtendedPayload>(encodedSdJwt, this.userConfig.hasher)
    return sdjwt.keys(this.userConfig.hasher)
  }

  public async presentableKeys(encodedSdJwt: SdJwtCompact) {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }
    const sdjwt = await SdJwt.fromEncode<Record<string, unknown>, ExtendedPayload>(encodedSdJwt, this.userConfig.hasher)
    return sdjwt.presentableKeys(this.userConfig.hasher)
  }

  public async getClaims(encodedSdJwt: SdJwtCompact): Promise<ExtendedPayload> {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }
    const sdjwt = await SdJwt.fromEncode<Record<string, unknown>, ExtendedPayload>(encodedSdJwt, this.userConfig.hasher)
    return sdjwt.getClaims<ExtendedPayload>(this.userConfig.hasher)
  }

  public toFlattenJson(encodedSdJwt: SdJwtCompact) {
    return FlattenJson.fromEncode(encodedSdJwt)
  }

  public toGeneralJson(encodedSdJwt: SdJwtCompact) {
    return GeneralJson.fromEncode(encodedSdJwt)
  }
}

export class SdJwtGeneralJsonInstance<ExtendedPayload extends SdJwtPayload> {
  //header type
  protected type?: string

  public static readonly defaultHashAlg = 'sha-256'

  protected userConfig: SdJwtConfig = {}

  constructor(userConfig?: SdJwtConfig) {
    if (userConfig) {
      if (userConfig.hashAlg && !IANA_HASH_ALGORITHMS.includes(userConfig.hashAlg)) {
        throw new SdJwtError(`Invalid hash algorithm: ${userConfig.hashAlg}`)
      }
      const allowedDisclosureHashAlgorithms =
        userConfig.allowedDisclosureHashAlgorithms ?? DEFAULT_SECURE_HASH_ALGORITHMS
      if (userConfig.hashAlg && !allowedDisclosureHashAlgorithms.includes(userConfig.hashAlg)) {
        throw new SdJwtError(`Disallowed hash algorithm: ${userConfig.hashAlg}`)
      }
      this.userConfig = userConfig
    }
  }

  private async createKbJwt(options: KbOptions, sdHash: string): Promise<KbJwt> {
    if (!this.userConfig.kbSigner) {
      throw new SdJwtError('Key Binding Signer not found')
    }
    if (!this.userConfig.kbSignAlg) {
      throw new SdJwtError('Key Binding sign algorithm not specified')
    }

    const { payload } = options
    const kbJwt = new KbJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: this.userConfig.kbSignAlg,
      },
      payload: { ...payload, sd_hash: sdHash },
    })

    await kbJwt.sign(this.userConfig.kbSigner)
    return kbJwt
  }

  private encodeObj(obj: Record<string, unknown>): string {
    return base64urlEncode(JSON.stringify(obj))
  }

  public async issue<Payload extends ExtendedPayload>(
    payload: Payload,
    disclosureFrame: DisclosureFrame<Payload> | undefined,
    options: {
      sigs: Array<{
        signer: Signer
        alg: string
        kid: string
        header?: Record<string, unknown>
      }> // multiple signers for the credential
    }
  ): Promise<GeneralJson> {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }

    if (!this.userConfig.saltGenerator) {
      throw new SdJwtError('SaltGenerator not found')
    }

    this.validateReservedFields<Payload>(payload)
    this.validateDisclosureFrame<Payload>(disclosureFrame)

    const hasher = this.userConfig.hasher
    const hashAlg = this.userConfig.hashAlg ?? SdJwtInstance.defaultHashAlg

    const { packedClaims, disclosures } = await pack(
      payload,
      disclosureFrame,
      { hasher, alg: hashAlg },
      this.userConfig.saltGenerator
    )

    const encodedSdJwtPayload = this.encodeObj({
      ...packedClaims,
      _sd_alg: disclosureFrame ? hashAlg : undefined,
    })

    const encodedDisclosures = disclosures.map((disclosure) => disclosure.encode())

    const signatures = await Promise.all(
      options.sigs.map(async (s) => {
        const { signer, alg, kid, header } = s
        const protectedHeader = { typ: this.type, alg, kid, ...header }
        const encodedProtectedHeader = this.encodeObj(protectedHeader)
        const signature = await signer(`${encodedProtectedHeader}.${encodedSdJwtPayload}`)

        return {
          protected: encodedProtectedHeader,
          signature,
        }
      })
    )

    const generalJson = new GeneralJson({
      payload: encodedSdJwtPayload,
      disclosures: encodedDisclosures,
      signatures,
    })

    return generalJson
  }

  /**
   * Validates if the payload contains any reserved claim names. If so it will throw an error.
   * @param payload
   * @returns
   */
  protected validateReservedFields<T extends ExtendedPayload>(payload: T) {
    validateReservedFieldsInternal(payload as Record<string, unknown>)
  }

  protected validateDisclosureFrame<T extends ExtendedPayload>(_disclosureFrame?: DisclosureFrame<T>) {
    return
  }

  public async present<T extends Record<string, unknown>>(
    generalJson: GeneralJson,
    presentationFrame?: PresentationFrame<T>,
    options?: {
      kb?: KbOptions
    }
  ): Promise<GeneralJson> {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }
    const hasher = this.userConfig.hasher
    const encodedSdJwt = generalJson.toEncoded(0)
    const sdjwt = await SdJwt.fromEncode(encodedSdJwt, hasher)
    if (sdjwt.kbJwt) {
      throw new SdJwtError('Holder cannot present an SD-JWT with KB-JWT')
    }

    if (!sdjwt.jwt?.payload) throw new SdJwtError('Payload not found')
    const disclosures = await sdjwt.getPresentDisclosures(presentationFrame, hasher)
    const encodedDisclosures = disclosures.map((d) => d.encode())
    const presentedGeneralJson = new GeneralJson({
      payload: generalJson.payload,
      disclosures: encodedDisclosures,
      signatures: generalJson.signatures,
    })

    if (!options?.kb) {
      return presentedGeneralJson
    }

    const presentSdJwtWithoutKb = await sdjwt.present(presentationFrame, hasher)

    const sdHashStr = await this.calculateSdHash(presentSdJwtWithoutKb, sdjwt, hasher)

    const kbJwt = await this.createKbJwt(options.kb, sdHashStr)
    const encodedKbJwt = kbJwt.encodeJwt()
    presentedGeneralJson.kb_jwt = encodedKbJwt
    return presentedGeneralJson
  }

  // This function is for verifying the SD JWT
  // If requiredClaimKeys is provided, it will check if the required claim keys are presentation in the SD JWT
  // If requireKeyBindings is true, it will check if the key binding JWT is presentation and verify it
  public async verify(generalJson: GeneralJson, options?: VerifierOptions) {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }
    const hasher = this.userConfig.hasher

    const { payload, headers } = await this.validate(generalJson, options)

    const encodedSdJwt = generalJson.toEncoded(0)
    const sdjwt = await SdJwt.fromEncode(encodedSdJwt, hasher)
    if (!sdjwt.jwt?.payload) {
      throw new SdJwtError('Invalid SD JWT')
    }

    if (options?.requiredClaimKeys) {
      const keys = await sdjwt.keys(hasher)
      const missingKeys = options?.requiredClaimKeys.filter((k) => !keys.includes(k))
      if (missingKeys.length > 0) {
        throw new SdJwtError(`Missing required claim keys: ${missingKeys.join(', ')}`)
      }
    }

    if (!options?.keyBindingNonce) {
      return { payload, headers }
    }

    if (!sdjwt.kbJwt) {
      throw new SdJwtError('Key Binding JWT not exist')
    }
    if (!this.userConfig.kbVerifier) {
      throw new SdJwtError('Key Binding Verifier not found')
    }
    const kb = await sdjwt.kbJwt.verifyKb({
      verifier: this.userConfig.kbVerifier,
      payload,
      nonce: options.keyBindingNonce,
      options,
    })
    if (!kb) {
      throw new Error('signature is not valid')
    }
    const sdHashfromKb = kb.payload.sd_hash
    const sdjwtWithoutKb = new SdJwt({
      jwt: sdjwt.jwt,
      disclosures: sdjwt.disclosures,
    })

    const presentSdJwtWithoutKb = sdjwtWithoutKb.encodeSdJwt()
    const sdHashStr = await this.calculateSdHash(presentSdJwtWithoutKb, sdjwt, hasher)

    if (sdHashStr !== sdHashfromKb) {
      throw new SdJwtError('Invalid sd_hash in Key Binding JWT')
    }

    return { payload, headers, kb }
  }

  private async calculateSdHash(presentSdJwtWithoutKb: string, sdjwt: SdJwt, hasher: Hasher) {
    if (!sdjwt.jwt?.payload) {
      throw new SdJwtError('Invalid SD JWT')
    }
    const { _sd_alg } = getSdAlgAndPayload(sdjwt.jwt.payload)
    const sdHash = await hasher(presentSdJwtWithoutKb, _sd_alg)
    const sdHashStr = uint8ArrayToBase64Url(sdHash)
    return sdHashStr
  }

  // This function is for validating the SD JWT
  // Just checking signature and return its the claims
  public async validate(generalJson: GeneralJson, options?: VerifierOptions) {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }
    if (!this.userConfig.verifier) {
      throw new SdJwtError('Verifier not found')
    }
    const hasher = this.userConfig.hasher
    const verifier = this.userConfig.verifier

    const { payload, signatures } = generalJson

    const results = await Promise.all(
      signatures.map(async (s) => {
        const { protected: encodedHeader, signature } = s
        const verified = await verifier(`${encodedHeader}.${payload}`, signature, {
          ...options,
          skipJwtClaimValidation: true,
        })
        const header = decodeBase64urlJsonStrict<Record<string, unknown>>(encodedHeader, 'Invalid JWT')
        if (typeof header.alg !== 'string' || header.alg === 'none') {
          throw new SdJwtError('Verify Error: alg "none" is not allowed')
        }
        if (options?.allowedIssuerAlgorithms && !options.allowedIssuerAlgorithms.includes(header.alg)) {
          throw new SdJwtError(`Verify Error: Disallowed alg ${header.alg}`)
        }
        // RFC 7515 Section 4.1.11, as in Jwt.verify
        if ('crit' in header) {
          throw new SdJwtError('Verify Error: unsupported critical header parameters')
        }
        return { verified, header }
      })
    )

    const verified = results.every((r) => r.verified)
    if (!verified) {
      throw new SdJwtError('Signature is not valid')
    }

    const encodedSdJwt = generalJson.toEncoded(0)
    const sdjwt = await SdJwt.fromEncode(encodedSdJwt, hasher)
    if (!sdjwt.jwt) {
      throw new SdJwtError('Invalid SD JWT')
    }

    const claims = await sdjwt.getClaims<ExtendedPayload>(hasher)
    // Validate that unpacked claims do not contain reserved field names
    validateReservedFieldsInternal(claims)
    validateJwtPayload(claims, options)
    return { payload: claims, headers: results.map((r) => r.header) }
  }

  public config(newConfig: SdJwtConfig) {
    this.userConfig = { ...this.userConfig, ...newConfig }
  }

  public encode(sdJwt: GeneralJson, index: number): SdJwtCompact {
    return sdJwt.toEncoded(index)
  }

  public decode(encodedSdJwt: SdJwtCompact) {
    return GeneralJson.fromEncode(encodedSdJwt)
  }

  public async keys(generalSdjwt: GeneralJson) {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }
    const encodedSdJwt = generalSdjwt.toEncoded(0)
    const sdjwt = await SdJwt.fromEncode(encodedSdJwt, this.userConfig.hasher)
    return sdjwt.keys(this.userConfig.hasher)
  }

  public async presentableKeys(generalSdjwt: GeneralJson) {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }
    const encodedSdJwt = generalSdjwt.toEncoded(0)
    const sdjwt = await SdJwt.fromEncode(encodedSdJwt, this.userConfig.hasher)
    return sdjwt.presentableKeys(this.userConfig.hasher)
  }

  public async getClaims(generalSdjwt: GeneralJson) {
    if (!this.userConfig.hasher) {
      throw new SdJwtError('Hasher not found')
    }
    const encodedSdJwt = generalSdjwt.toEncoded(0)
    const sdjwt = await SdJwt.fromEncode(encodedSdJwt, this.userConfig.hasher)
    return sdjwt.getClaims(this.userConfig.hasher)
  }
}
