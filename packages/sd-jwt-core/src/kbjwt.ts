import { nowInSeconds } from '@owf/identity-common'
import { getJwtTimeValidationOptions, Jwt, type VerifierOptions, validateJwtPayload } from './jwt'
import { timeClaimException } from './time-claim-error'
import { KB_JWT_TYP, type KbVerifier, type kbHeader, type kbPayload } from './types'
import { SDJWTException } from './utils'

export class KBJwt<Header extends kbHeader = kbHeader, Payload extends kbPayload = kbPayload> extends Jwt<
  Header,
  Payload
> {
  // Checking the validity of the key binding jwt
  // the type unknown is not good, but we don't know at this point how to get the public key of the signer, this is defined in the kbVerifier
  public async verifyKB(values: {
    verifier: KbVerifier
    payload: Record<string, unknown>
    nonce: string
    /**
     * Full verification options. The SD-JWT verifier validates issuer-signed
     * claims and the issuer algorithm before calling verifyKB; key-binding-specific
     * constraints are checked here. Only time-validation options reach Jwt.verify.
     */
    options?: VerifierOptions
  }) {
    if (!this.header || !this.payload || !this.signature) {
      throw new SDJWTException('Verify Error: Invalid JWT')
    }

    if (
      typeof this.header.alg !== 'string' ||
      this.header.alg === 'none' ||
      typeof this.header.typ !== 'string' ||
      this.header.typ !== KB_JWT_TYP ||
      typeof this.payload.iat !== 'number' ||
      typeof this.payload.aud !== 'string' ||
      typeof this.payload.nonce !== 'string' ||
      typeof this.payload.sd_hash !== 'string' ||
      this.payload.sd_hash.length === 0
    ) {
      throw new SDJWTException('Invalid Key Binding Jwt')
    }

    if (this.payload.nonce !== values.nonce) {
      throw new SDJWTException('Verify Error: Invalid Nonce')
    }

    if (values.options?.expectedKeyBindingAudience !== undefined) {
      const expectedAudiences = Array.isArray(values.options.expectedKeyBindingAudience)
        ? values.options.expectedKeyBindingAudience
        : [values.options.expectedKeyBindingAudience]
      if (!expectedAudiences.includes(this.payload.aud)) {
        throw new SDJWTException('Verify Error: Invalid Key Binding audience')
      }
    }

    if (values.options?.keyBindingMaxAgeSeconds !== undefined) {
      const currentDate = values.options.currentDate ?? nowInSeconds()
      const skew = values.options.skewSeconds ?? 0
      if (this.payload.iat + values.options.keyBindingMaxAgeSeconds + skew < currentDate) {
        throw timeClaimException('key-binding-jwt', 'tooOld', {
          claim: 'iat',
          value: this.payload.iat,
          currentDate,
          skewSeconds: skew,
          maxAgeSeconds: values.options.keyBindingMaxAgeSeconds,
        })
      }
    }

    // Only the time claims (iat, nbf, exp) are checked: issuer-signed constraints
    // such as the expected issuer or vct do not apply to the KB-JWT. They are
    // checked here instead of in Jwt.verify, so failures name the Key Binding JWT
    // and carry the KEY_BINDING_JWT_* codes.
    validateJwtPayload(this.payload, getJwtTimeValidationOptions(values.options), 'key-binding-jwt')

    // Jwt.verify checks the signature. The wrapper passes the credential payload
    // (including the holder's cnf key) to kbVerifier instead of verifier options.
    await this.verify((data, sig) => values.verifier(data, sig, values.payload), { skipJwtClaimValidation: true })

    return { payload: this.payload, header: this.header }
  }

  // This function is for creating KBJwt object for verify properly
  public static fromKBEncode<Header extends kbHeader = kbHeader, Payload extends kbPayload = kbPayload>(
    encodedJwt: string
  ): KBJwt<Header, Payload> {
    const { header, payload, signature } = Jwt.decodeJWT<Header, Payload>(encodedJwt)

    const jwt = new KBJwt<Header, Payload>({
      header,
      payload,
      signature,
      encoded: encodedJwt,
    })

    return jwt
  }
}
