import { nowInSeconds } from '@owf/identity-common'
import { Jwt, type VerifierOptions, validateJwtPayload } from './jwt'
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
     * Options forwarded to the common JWT verification, e.g. currentDate and
     * skewSeconds used to validate the iat, nbf and exp claims.
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

    // The common JWT claim validation (iat, nbf, exp) runs here instead of in
    // Jwt.verify, so its errors name the Key Binding JWT and carry the
    // KEY_BINDING_JWT_* codes rather than those of the issuer-signed JWT.
    if (!values.options?.skipJwtClaimValidation) {
      validateJwtPayload(this.payload, values.options, 'key-binding-jwt')
    }

    // Delegate signature verification to the shared Jwt.verify implementation.
    // The kbVerifier needs the kb+jwt payload (e.g. the holder's cnf key), so we
    // wrap it to forward values.payload instead of the base verifier's options
    // argument.
    await this.verify((data, sig) => values.verifier(data, sig, values.payload), {
      ...values.options,
      skipJwtClaimValidation: true,
    })

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
