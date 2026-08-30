import { Tag } from 'cbor-x'
import type { AnyCborStructure, DecodedStructureType, EncodedStructureType } from '../cbor'
import { cborDecode, describeCborValue } from '../cbor'
import type { AnyCwtPayload, CwtPayload } from './claims/cwt-payload'
import { CosePayloadInvalidStructureError, CwtDetachedPayloadError, CwtPayloadDecodeError } from './error'
import {
  type ProtectedHeaderOptions,
  ProtectedHeaders,
  RegisteredCwtHeaderClaimKey,
  type SignatureAlgorithm,
  type UnprotectedHeaderOptions,
  UnprotectedHeaders,
} from './headers'
import type { CoseKey } from './key'
import { Mac0, type Mac0Context } from './mac0'
import { Sign1, type Sign1Context } from './sign1'

/**
 * The CWT CBOR tag, defined in RFC 8392. It wraps the COSE structure rather than replacing it,
 * so a token tagged with it must be unwrapped before the COSE structure can be decoded.
 */
const CWT_TAG = 61

/**
 * A raw header map is only accepted for a CWT that uses the default header structures. A CWT type
 * with its own header class has to be given an instance of that class, so that the map is validated
 * against the class's schema instead of the registered COSE header claims.
 */
type RawHeadersFor<Headers, Raw> = ProtectedHeaders extends Headers
  ? Raw
  : UnprotectedHeaders extends Headers
    ? Raw
    : never

export type CwtOptions<
  Payload extends AnyCwtPayload = CwtPayload,
  ProtectedHeadersStructure extends AnyProtectedHeaders = ProtectedHeaders,
  UnprotectedHeadersStructure extends AnyUnprotectedHeaders = UnprotectedHeaders,
> = {
  protectedHeaders?:
    | ProtectedHeadersStructure
    | RawHeadersFor<ProtectedHeadersStructure, ProtectedHeaderOptions['protectedHeaders']>
  unprotectedHeaders?:
    | UnprotectedHeadersStructure
    | RawHeadersFor<UnprotectedHeadersStructure, UnprotectedHeaderOptions['unprotectedHeaders']>

  /** The CWT claims set. */
  payload: Payload

  /** The COSE_Sign1 signature or the COSE_Mac0 authentication tag, when the CWT carries one. */
  signatureOrTag?: Uint8Array

  externalAad?: Uint8Array

  /**
   * The payload bytes exactly as they appeared in the COSE message. Set when decoding a token, so
   * that verification can use them directly rather than re-encoding the decoded payload. Do not
   * pass this when constructing a CWT yourself.
   *
   * @see {@link Cwt.payloadBytes}
   */
  originalPayloadBytes?: Uint8Array
}

// biome-ignore lint/suspicious/noExplicitAny: intentionally unconstrained, used as a generic bound
export type AnyProtectedHeaders = ProtectedHeaders<any>
// biome-ignore lint/suspicious/noExplicitAny: intentionally unconstrained, used as a generic bound
export type AnyUnprotectedHeaders = UnprotectedHeaders<any>

// biome-ignore lint/suspicious/noExplicitAny: intentionally unconstrained, used as a generic bound
export type AnyCwt = Cwt<any, any, any>

// biome-ignore lint/suspicious/noExplicitAny: matching any header structure
export type CwtPayloadType<T> = T extends Cwt<infer Payload, any, any> ? Payload : never
// biome-ignore lint/suspicious/noExplicitAny: matching any payload/header structure
export type CwtProtectedHeadersType<T> = T extends Cwt<any, infer Headers, any> ? Headers : never
// biome-ignore lint/suspicious/noExplicitAny: matching any payload/header structure
export type CwtUnprotectedHeadersType<T> = T extends Cwt<any, any, infer Headers> ? Headers : never

/**
 * The static side of a `CborStructure` subclass, reduced to what decoding a CWT needs: constructing
 * an instance, and validating an encoded structure into a decoded one. Kept structural rather than
 * `typeof SomeClass` so that any subclass is accepted.
 */
export type CwtStructureClass<Structure extends AnyCborStructure> = {
  new (structure: DecodedStructureType<Structure>): Structure
  fromEncodedStructure(encodedStructure: EncodedStructureType<Structure>): {
    decodedStructure: DecodedStructureType<Structure>
  }
}

/**
 * The structure classes a token is decoded into. Passed to {@link Cwt.fromToken}, which is the only
 * place that has to turn bytes back into structures, rather than declared as statics on the class:
 * a CWT type that wants to hide them overrides `fromToken` and supplies them there.
 */
export type CwtStructures<T extends AnyCwt> = {
  payload: CwtStructureClass<CwtPayloadType<T>>
  protectedHeaders?: CwtStructureClass<CwtProtectedHeadersType<T>>
  unprotectedHeaders?: CwtStructureClass<CwtUnprotectedHeadersType<T>>
}

/**
 * The static side of a `Cwt` subclass, so `fromToken` can construct (and type) the subclass it was
 * called on rather than the base class.
 */
export type CwtStaticThis<T extends AnyCwt> = {
  new (options: CwtOptions<CwtPayloadType<T>, CwtProtectedHeadersType<T>, CwtUnprotectedHeadersType<T>>): T
}

/**
 * A CBOR Web Token (RFC 8392): a COSE_Sign1 or COSE_Mac0 whose payload is a CWT claims set.
 *
 * A CWT type is expressed by the structures it is made of: a {@link CwtPayload} subclass for the
 * claims set, and a {@link ProtectedHeaders} / {@link UnprotectedHeaders} subclass for a header
 * bucket whose labels it adds to or narrows. Each of those validates itself through its own
 * `encodingSchema`, so `Cwt` holds no schemas and needs no per-type statics.
 *
 * The classes are named where a token is turned back into structures, which is `fromToken`:
 *
 * ```ts
 * const cwt = Cwt.fromToken(token, {
 *   payload: StatusListCwtPayload,
 *   protectedHeaders: StatusListCwtProtectedHeaders,
 * })
 *
 * cwt.payload.statusList // typed
 * ```
 *
 * A CWT type that carries extra logic subclasses `Cwt` and overrides `fromToken` to supply them, so
 * callers do not repeat the classes:
 *
 * ```ts
 * class StatusListCwt extends Cwt<StatusListCwtPayload, StatusListCwtProtectedHeaders> {
 *   public static override fromToken(token: Uint8Array) {
 *     return super.fromToken(token, {
 *       payload: StatusListCwtPayload,
 *       protectedHeaders: StatusListCwtProtectedHeaders,
 *     })
 *   }
 * }
 * ```
 *
 * @template Payload - The claims set structure for this CWT type.
 * @template ProtectedHeadersStructure - The protected header structure for this CWT type.
 * @template UnprotectedHeadersStructure - The unprotected header structure for this CWT type.
 */
export class Cwt<
  Payload extends AnyCwtPayload = CwtPayload,
  ProtectedHeadersStructure extends AnyProtectedHeaders = ProtectedHeaders,
  UnprotectedHeadersStructure extends AnyUnprotectedHeaders = UnprotectedHeaders,
> {
  public payload: Payload
  public protectedHeaders: ProtectedHeadersStructure
  public unprotectedHeaders: UnprotectedHeadersStructure
  public externalAad?: Uint8Array

  /** The COSE_Sign1 signature or COSE_Mac0 authentication tag, when the CWT carries one. */
  public signatureOrTag?: Uint8Array

  /**
   * The payload bytes as received in the COSE message, kept so that verification can use them
   * directly. RFC 9052 puts the payload into `Sig_structure`/`MAC_structure` as an opaque `bstr`, so
   * what was signed is the exact bytes the issuer sent, not whatever we would encode the decoded
   * payload back into. Cleared by {@link markPayloadModified}, since the signature over it no longer
   * means anything once the payload changed.
   *
   * @see https://datatracker.ietf.org/doc/rfc9052/#section-4.4
   * @see https://datatracker.ietf.org/doc/rfc9052/#section-6
   */
  private originalPayloadBytes?: Uint8Array

  public constructor(options: CwtOptions<Payload, ProtectedHeadersStructure, UnprotectedHeadersStructure>) {
    this.payload = options.payload

    // A raw map only reaches here for a CWT using the default header structures, see `RawHeadersFor`.
    // `create` validates it, so the headers of every CWT are checked by their own schema.
    this.protectedHeaders = (
      options.protectedHeaders instanceof ProtectedHeaders
        ? options.protectedHeaders
        : ProtectedHeaders.create({ protectedHeaders: options.protectedHeaders as Map<number, unknown> | undefined })
    ) as ProtectedHeadersStructure
    this.unprotectedHeaders = (
      options.unprotectedHeaders instanceof UnprotectedHeaders
        ? options.unprotectedHeaders
        : UnprotectedHeaders.create({
            unprotectedHeaders: options.unprotectedHeaders as Map<number, unknown> | undefined,
          })
    ) as UnprotectedHeadersStructure

    this.signatureOrTag = options.signatureOrTag
    this.externalAad = options.externalAad
    this.originalPayloadBytes = options.originalPayloadBytes
  }

  public static create<T extends AnyCwt>(
    this: CwtStaticThis<T>,
    options: CwtOptions<CwtPayloadType<T>, CwtProtectedHeadersType<T>, CwtUnprotectedHeadersType<T>>
  ): T {
    return new this(options)
  }

  /**
   * Decodes a CWT from a tagged COSE_Sign1 (tag 18) or COSE_Mac0 (tag 17) token.
   *
   * @throws CborDecodeError if the token is not valid CBOR.
   * @throws CosePayloadInvalidStructureError if the token is valid CBOR but not a COSE_Sign1/COSE_Mac0.
   * @throws CwtDetachedPayloadError if the token carries a detached (null) payload.
   * @throws CwtPayloadDecodeError if the payload is not a valid claims set for this CWT type. The
   *   underlying error is available on the `cause` property.
   * @throws ZodValidationError if a header map is not valid for this CWT type's header structures.
   */
  public static fromToken<T extends AnyCwt>(
    this: CwtStaticThis<T>,
    token: Uint8Array,
    structures: CwtStructures<T>
  ): T {
    const coseStructure = Cwt.decodeCoseStructure(token)

    const payloadBytes = coseStructure.payload
    if (!payloadBytes) {
      throw new CwtDetachedPayloadError(
        'Cwt does not contain a payload, a detached payload is not supported for a CWT as the claims set cannot be decoded'
      )
    }

    let payload: CwtPayloadType<T>
    try {
      payload = decodeStructure(structures.payload, cborDecode(payloadBytes))
    } catch (error) {
      throw new CwtPayloadDecodeError(
        `Unable to decode CWT payload: ${error instanceof Error ? error.message : String(error)}`,
        { cause: error }
      )
    }

    // The COSE structure only knows the base header classes, so the maps are re-read through this
    // CWT type's header structures, which is what validates them against its schema.
    const protectedHeaders = structures.protectedHeaders
      ? decodeStructure(
          structures.protectedHeaders,
          coseStructure.protectedHeaders.encodedStructure as EncodedStructureType<CwtProtectedHeadersType<T>>
        )
      : (coseStructure.protectedHeaders as CwtProtectedHeadersType<T>)
    const unprotectedHeaders = structures.unprotectedHeaders
      ? decodeStructure(
          structures.unprotectedHeaders,
          coseStructure.unprotectedHeaders.encodedStructure as EncodedStructureType<CwtUnprotectedHeadersType<T>>
        )
      : (coseStructure.unprotectedHeaders as CwtUnprotectedHeadersType<T>)

    return new this({
      payload,
      protectedHeaders,
      unprotectedHeaders,
      signatureOrTag: coseStructure instanceof Sign1 ? coseStructure.signature : coseStructure.tag,
      // Keep the exact bytes the issuer signed, see `originalPayloadBytes`.
      originalPayloadBytes: new Uint8Array(payloadBytes),
    })
  }

  /**
   * Decodes the COSE structure wrapping the CWT claims set.
   *
   * @throws CborDecodeError if the token is not valid CBOR.
   * @throws CosePayloadInvalidStructureError if the token is valid CBOR but not a COSE_Sign1/COSE_Mac0.
   */
  public static decodeCoseStructure(token: Uint8Array): Sign1 | Mac0 {
    const decoded = cborDecode<unknown>(token)

    // The tag 18/17 cbor-x extensions turn a COSE token into a Sign1/Mac0 instance. Anything
    // else decoded fine as CBOR but isn't a COSE token, and would otherwise be accepted here
    // and only surface much later as a confusing 'payload is missing' error.
    if (!(decoded instanceof Sign1) && !(decoded instanceof Mac0)) {
      const cwtTagHint =
        decoded instanceof Tag && decoded.tag === CWT_TAG ? ' (the CWT tag, which must be unwrapped first)' : ''

      throw new CosePayloadInvalidStructureError(
        `Expected a tagged COSE_Sign1 (tag ${Sign1.tag}) or COSE_Mac0 (tag ${Mac0.tag}) structure, but decoded ${describeCborValue(decoded)}${cwtTagHint}. ` +
          'An untagged COSE structure is not supported; decode it with Sign1.decode or Mac0.decode instead.'
      )
    }

    return decoded
  }

  /**
   * The payload bytes that are signed or authenticated: the bytes as received when this CWT was
   * decoded from a token and the payload has not been modified since, and the re-encoded payload
   * otherwise.
   */
  public get payloadBytes(): Uint8Array {
    return this.originalPayloadBytes ?? this.payload.encode()
  }

  /**
   * Drops the retained {@link originalPayloadBytes}, so that the payload is re-encoded on the next
   * signing or verification. Call this from a subclass after mutating the payload.
   */
  protected markPayloadModified() {
    this.originalPayloadBytes = undefined
  }

  /**
   * `typ` (16), the media type of this CWT.
   *
   * Read from the protected headers only: RFC 9596 states that the `typ` parameter MUST NOT be
   * present in unprotected headers, so an unprotected one is not authoritative and reading it would
   * let anyone who can alter the token change what the token claims to be.
   *
   * @see https://www.rfc-editor.org/rfc/rfc9596.html#section-2
   */
  public get typ(): string | number | undefined {
    return this.protectedHeaders.headers.get(RegisteredCwtHeaderClaimKey.Typ)
  }

  /**
   * `alg` (1), the algorithm the CWT is signed or authenticated with.
   *
   * Read from the protected headers only. RFC 9052 requires `alg` to be authenticated, which for a
   * single recipient structure (COSE_Sign1 / COSE_Mac0) means the protected bucket or the externally
   * supplied data. An unprotected `alg` is attacker controlled, and is also not what
   * `Sign1.algorithm` / `Mac0.algorithm` pass to verification, so reading it here would report an
   * algorithm the signature was never checked against.
   *
   * @see https://www.rfc-editor.org/rfc/rfc9052.html#section-3.1
   */
  public get algorithm(): string | number | undefined {
    return this.protectedHeaders.headers.get(RegisteredCwtHeaderClaimKey.Algorithm)
  }

  /**
   * `kid` (4), a hint for which key to verify with.
   *
   * Read from the protected headers, falling back to the unprotected ones: RFC 9052 calls `kid` a
   * hint that "is not a security-critical field" and explicitly allows it in the unprotected bucket,
   * where it is commonly placed.
   *
   * @see https://www.rfc-editor.org/rfc/rfc9052.html#section-3.1
   */
  public get keyId(): Uint8Array | undefined {
    return (
      this.protectedHeaders.headers.get(RegisteredCwtHeaderClaimKey.KeyId) ??
      this.unprotectedHeaders.headers.get(RegisteredCwtHeaderClaimKey.KeyId)
    )
  }

  public get asSign1() {
    return Sign1.create({
      protectedHeaders: this.protectedHeaders,
      unprotectedHeaders: this.unprotectedHeaders,
      payload: this.payloadBytes,
      signature: this.signatureOrTag,
      externalAad: this.externalAad,
    })
  }

  public get asMac0() {
    return Mac0.create({
      protectedHeaders: this.protectedHeaders,
      unprotectedHeaders: this.unprotectedHeaders,
      payload: this.payloadBytes,
      tag: this.signatureOrTag,
      externalAad: this.externalAad,
    })
  }

  public async signAndEncode(
    options: { signingKey: CoseKey; algorithm?: SignatureAlgorithm },
    ctx: Pick<Sign1Context, 'sign'>
  ) {
    return (await this.asSign1.sign(options, ctx)).encode()
  }

  public async authenticateAndEncode({ key }: { key: CoseKey }, ctx: Pick<Mac0Context, 'authenticate'>) {
    return (await this.asMac0.authenticate({ key }, ctx)).encode()
  }

  public async verifySignature({ key }: { key: CoseKey }, ctx: Pick<Sign1Context, 'verify'>) {
    return await this.asSign1.verifySignature({ key }, ctx)
  }

  public async verifyAuthenticationCode({ key }: { key: CoseKey }, ctx: Pick<Mac0Context, 'verify'>) {
    return await this.asMac0.verifyAuthenticationCode({ key }, ctx)
  }
}

/**
 * Builds a structure instance from its encoded form, validating it against the class's own
 * `encodingSchema`. Mirrors `CborStructure.decode`, but for a class passed in as a value rather than
 * called as a static, which is how a CWT names the structures it is made of.
 */
function decodeStructure<Structure extends AnyCborStructure>(
  structureClass: CwtStructureClass<Structure>,
  encodedStructure: EncodedStructureType<Structure>
): Structure {
  return new structureClass(structureClass.fromEncodedStructure(encodedStructure).decodedStructure)
}
