import { Tag } from 'cbor-x'
import type { AnyCborStructure, EncodedStructureType } from '../cbor'
import { cborDecode, describeCborValue } from '../cbor'
import type { AnyCwtPayload, CwtPayload } from './claims/cwt-payload'
import {
  CoseInvalidSignatureError,
  CosePayloadInvalidStructureError,
  CwtDetachedPayloadError,
  CwtMissingVerifyContextError,
  CwtNotSignedError,
  CwtPayloadDecodeError,
} from './error'
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

  /**
   * The COSE_Sign1 signature over the payload. Set for a signed CWT, and mutually exclusive with
   * {@link tag} — a CWT is one or the other.
   */
  signature?: Uint8Array

  /**
   * The COSE_Mac0 authentication tag over the payload. Set for a MACed CWT, and mutually exclusive
   * with {@link signature}.
   */
  tag?: Uint8Array

  /**
   * The payload bytes exactly as they appeared in the COSE message. Set when decoding a token, so
   * that verification can use them directly rather than re-encoding the decoded payload. Do not
   * pass this when constructing a CWT yourself.
   *
   * @see {@link Cwt.payloadBytes}
   */
  originalPayloadBytes?: Uint8Array
}

/**
 * The verification context {@link Cwt.verify} needs. Both are optional, so a caller that only deals
 * with one of the two COSE structures passes only that one, and a CWT carried in the other is
 * rejected rather than verified with the wrong context.
 */
export type CwtVerifyContext = {
  /** Verifies the signature of a CWT carried in a COSE_Sign1. */
  sign1?: Pick<Sign1Context, 'verify'>

  /** Verifies the authentication tag of a CWT carried in a COSE_Mac0. */
  mac0?: Pick<Mac0Context, 'verify'>
}

/**
 * The options the payload of `Cwt` takes for claim verification. Reading them off the payload class
 * is what lets a CWT type require its own options — a status list CWT its `uri`, say — on the `Cwt`
 * methods that forward to it.
 */
export type CwtClaimsOptionsFor<Payload extends AnyCwtPayload> = NonNullable<Parameters<Payload['verifyClaims']>[0]>

/** The options {@link Cwt.verify} takes: the key, the claim options of its payload, and the AAD. */
export type CwtVerifyOptions<Payload extends AnyCwtPayload> = {
  key: CoseKey

  /**
   * Externally supplied data covered by the signature or authentication tag. It is not carried in
   * the token, so it has to be the same value the issuer signed with.
   */
  externalAad?: Uint8Array
} & CwtClaimsOptionsFor<Payload>

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
 * The static side of a `CborStructure` subclass, reduced to what decoding a CWT needs: turning an
 * encoded structure into a validated instance. Kept structural rather than `typeof SomeClass` so
 * that any subclass is accepted.
 */
export type CwtStructureClass<Structure extends AnyCborStructure> = {
  fromEncodedStructure(encodedStructure: EncodedStructureType<Structure>): Structure
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
  #payload: Payload

  /**
   * The claims set of this CWT.
   *
   * Assignable, and assigning drops the retained {@link originalPayloadBytes}, so the new claims set
   * is what gets signed or verified. Mutating the claims set in place cannot be seen from here, so
   * call {@link markPayloadModified} after doing so — the mutation helpers a CWT type exposes, such
   * as `StatusListCwt.updateStatusList`, already do.
   */
  public get payload(): Payload {
    return this.#payload
  }

  public set payload(payload: Payload) {
    this.#payload = payload
    this.markPayloadModified()
  }

  public protectedHeaders: ProtectedHeadersStructure
  public unprotectedHeaders: UnprotectedHeadersStructure

  /**
   * The COSE_Sign1 signature over the payload, for a signed CWT.
   *
   * Kept apart from {@link tag} rather than as one 'signature or tag' value, because which of the
   * two a CWT carries is what says whether it is a COSE_Sign1 or a COSE_Mac0 — a distinction the
   * encoded structure does not carry, and that {@link verify} needs.
   */
  public signature?: Uint8Array

  /** The COSE_Mac0 authentication tag over the payload, for a MACed CWT. See {@link signature}. */
  public tag?: Uint8Array

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
    // Set the field rather than going through the setter: there is nothing to invalidate yet, and
    // `originalPayloadBytes` is assigned below.
    this.#payload = options.payload

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

    if (options.signature && options.tag) {
      throw new CosePayloadInvalidStructureError(
        'A CWT carries either a COSE_Sign1 signature or a COSE_Mac0 authentication tag, not both'
      )
    }

    this.signature = options.signature
    this.tag = options.tag
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
      signature: coseStructure instanceof Sign1 ? coseStructure.signature : undefined,
      tag: coseStructure instanceof Mac0 ? coseStructure.tag : undefined,
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
   * signing or verification. Call this after mutating {@link payload} in place, from a subclass or
   * from outside; assigning a new payload marks it automatically.
   */
  public markPayloadModified() {
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

  /** The proof this CWT carries, whichever of the two it is: its {@link signature} or its {@link tag}. */
  public get signatureOrTag(): Uint8Array | undefined {
    return this.signature ?? this.tag
  }

  public get asSign1() {
    return Sign1.create({
      protectedHeaders: this.protectedHeaders,
      unprotectedHeaders: this.unprotectedHeaders,
      payload: this.payloadBytes,
      signature: this.signature,
    })
  }

  public get asMac0() {
    return Mac0.create({
      protectedHeaders: this.protectedHeaders,
      unprotectedHeaders: this.unprotectedHeaders,
      payload: this.payloadBytes,
      tag: this.tag,
    })
  }

  public async signAndEncode(
    options: { signingKey: CoseKey; algorithm?: SignatureAlgorithm; externalAad?: Uint8Array },
    ctx: Pick<Sign1Context, 'sign'>
  ) {
    return (await this.asSign1.sign(options, ctx)).encode()
  }

  public async authenticateAndEncode(
    options: { key: CoseKey; externalAad?: Uint8Array },
    ctx: Pick<Mac0Context, 'authenticate'>
  ) {
    return (await this.asMac0.authenticate(options, ctx)).encode()
  }

  /**
   * Verifies the claims of this CWT's payload. See `CwtPayload.verifyClaims` for what is checked; a
   * CWT type that narrows its payload class narrows this along with it, options included.
   *
   * This checks the claims only. {@link verify} checks the signature or authentication tag as well,
   * and is what a verifier wants: the claims of a token whose issuer has not been established mean
   * nothing.
   *
   * @throws CwtClaimVerificationError if a required claim is missing, a claim does not match what
   *   was expected, or the token is outside its validity window.
   */
  public verifyClaims(options: CwtClaimsOptionsFor<Payload>): void {
    this.payload.verifyClaims(options)
  }

  /**
   * Verifies this CWT completely: the signature or authentication tag over the payload, and then
   * the claims in it.
   *
   * Which of the two is checked follows whether this CWT carries a {@link signature} or a
   * {@link tag}, and the matching entry of `ctx` is used, so a caller does not have to know which
   * of the two structures a token turned out to be.
   *
   * @throws CwtNotSignedError if the CWT carries neither, and so has nothing to verify.
   * @throws CwtMissingVerifyContextError if `ctx` has no entry for the structure this CWT is.
   * @throws CoseInvalidSignatureError if the signature or authentication tag does not verify.
   * @throws CwtClaimVerificationError if the claims do not, see {@link verifyClaims}.
   */
  public async verify(
    { key, externalAad, ...claimsOptions }: CwtVerifyOptions<Payload>,
    ctx: CwtVerifyContext
  ): Promise<void> {
    if (this.tag !== undefined) {
      if (!ctx.mac0) {
        throw new CwtMissingVerifyContextError(
          'The CWT carries a COSE_Mac0 authentication tag, but no `mac0` verification context was provided'
        )
      }

      if (!(await this.verifyAuthenticationCode({ key, externalAad }, ctx.mac0))) {
        throw new CoseInvalidSignatureError(
          'The authentication tag of the CWT could not be verified with the provided key'
        )
      }
    } else if (this.signature !== undefined) {
      if (!ctx.sign1) {
        throw new CwtMissingVerifyContextError(
          'The CWT carries a COSE_Sign1 signature, but no `sign1` verification context was provided'
        )
      }

      if (!(await this.verifySignature({ key, externalAad }, ctx.sign1))) {
        throw new CoseInvalidSignatureError('The signature of the CWT could not be verified with the provided key')
      }
    } else {
      throw new CwtNotSignedError(
        'The CWT carries neither a signature nor an authentication tag, so there is nothing to verify. ' +
          'Decode a signed or authenticated token with `fromToken` to verify it.'
      )
    }

    // NOTE: cast because TypeScript cannot see that the rest of a generic intersection is still the
    // payload's options type.
    this.verifyClaims(claimsOptions as CwtClaimsOptionsFor<Payload>)
  }

  public async verifySignature(options: { key: CoseKey; externalAad?: Uint8Array }, ctx: Pick<Sign1Context, 'verify'>) {
    return await this.asSign1.verifySignature(options, ctx)
  }

  public async verifyAuthenticationCode(
    options: { key: CoseKey; externalAad?: Uint8Array },
    ctx: Pick<Mac0Context, 'verify'>
  ) {
    return await this.asMac0.verifyAuthenticationCode(options, ctx)
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
  // NOTE: the instance `fromEncodedStructure` builds is used as is, rather than re-wrapped around
  // its decoded structure: a structure can carry more than that map — `ProtectedHeaders` keeps the
  // bstr it was decoded from — and re-wrapping would drop it.
  return structureClass.fromEncodedStructure(encodedStructure)
}
