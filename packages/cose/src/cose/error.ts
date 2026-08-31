// biome-ignore format: no explanation
class CoseError extends Error {
  // NOTE: declared explicitly rather than passing `{ cause }` to `super`, as the
  // project targets ES2020 and `Error.cause` was only added in ES2022.
  public readonly cause?: unknown

  constructor(message: string = new.target.name, options?: { cause?: unknown }) {
    super(message)
    this.name = new.target.name
    this.cause = options?.cause
  }
}

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
 * the value it was expected to have, or the token is outside its validity window.
 */
export class CwtClaimVerificationError extends CoseError {}
