import { type CommonValidationCode, IdentityError, ValidationError, type ValidationIssueOf } from '@owf/identity-common'

/**
 * Base error class for the COSE structures in this package.
 *
 * Extends `IdentityError` so that a caller can catch every error raised by the identity-common
 * packages in one place.
 */
export class CoseError extends IdentityError {
  // NOTE: declared explicitly rather than passing `{ cause }` to `super`, as the
  // project targets ES2020 and `Error.cause` was only added in ES2022.
  public readonly cause?: unknown

  constructor(message: string = new.target.name, options?: { cause?: unknown; details?: unknown }) {
    super(message, options?.details)
    this.name = new.target.name
    this.cause = options?.cause
  }
}

/** A COSE or CBOR structure does not match its schema, with the `issues` of the validation */
export class CoseValidationError extends ValidationError {}

export class CoseUnsupportedMacError extends CoseError {}
export class CoseInvalidSignatureError extends CoseError {}
export class CoseInvalidAlgorithmError extends CoseError {}
export class CosePayloadMustBeNullError extends CoseError {}
export class CosePayloadMustBeDefinedError extends CoseError {}
export class CosePayloadInvalidStructureError extends CoseError {}
export class CoseInvalidTypeForKeyError extends CoseError {}
export class CoseInvalidValueForKtyError extends CoseError {}
export class CoseInvalidKtyForRawError extends CoseError {}
export class CoseXNotDefinedError extends CoseError {}
export class CoseYNotDefinedError extends CoseError {}
export class CoseDNotDefinedError extends CoseError {}
export class CoseKNotDefinedError extends CoseError {}
export class CoseEphemeralMacKeyIsRequiredError extends CoseError {}
export class CoseCertificateNotFoundError extends CoseError {}

/**
 * RFC 9360: the end-entity certificate "MUST be integrity protected by COSE". An `x5chain` in the
 * unprotected header is therefore only accepted when a protected `x5t` matches its leaf.
 */
export class CoseX5ChainNotBoundError extends CoseError {}
export class CoseKeyTypeNotSupportedForPrivateKeyExtractionError extends CoseError {}

/** The CWT carries a detached payload (`null`), which cannot be decoded into a claims set. */
export class CwtDetachedPayloadError extends CoseError {}

/** The CWT payload is not a valid claims set for the CWT type it was decoded as. */
export class CwtPayloadDecodeError extends CoseError {}

/** The CWT carries neither a signature nor an authentication tag, so there is nothing to verify. */
export class CwtNotSignedError extends CoseError {}

/** No verification context was provided for the COSE structure the CWT is carried in. */
export class CwtMissingVerifyContextError extends CoseError {}

/**
 * A claim required by the profile the token is verified against is missing, a claim does not match
 * the value it was expected to have, or the token is outside its validity window. Each with an issue
 * of `VALIDATION_CODES`: `claim_missing`, `claim_value_mismatch`, `expired` or `not_yet_valid`, at
 * the key of the claim.
 */
export class CwtClaimVerificationError extends ValidationError<ValidationIssueOf<CommonValidationCode>> {}
