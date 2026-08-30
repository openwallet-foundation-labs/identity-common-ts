import { dateToSeconds, secondsToDate } from '@owf/identity-common'
import z from 'zod'
import { CborStructure } from '../../cbor/cbor-structure.js'
import {
  type AnyTypedMap,
  type EntriesBase,
  type ExtendedEntries,
  extendTypedMapEntries,
  TypedMap,
  typedMap,
} from '../../utils/typed-map.js'
import { zUint8Array } from '../../utils/zod.js'
import { RegisteredCwtClaimKey } from './default.js'

/**
 * A CWT NumericDate: the number of seconds since the epoch, as an integer or a floating-point
 * number.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8392#section-2
 */
export const zCwtNumericDate = z.number()

/**
 * The registered CWT claims (RFC 8392 Section 3.1), as `typedMap` entries.
 *
 * All of them are optional: RFC 8392 does not require any claim to be present, and which claims a
 * token must carry is decided by the CWT type. A specific CWT builds on these with
 * {@link extendCwtPayloadClaims}, and can make a claim required by redeclaring it.
 */
export const cwtPayloadClaimEntries = [
  [RegisteredCwtClaimKey.Issuer, z.string().exactOptional()],
  [RegisteredCwtClaimKey.Subject, z.string().exactOptional()],
  // RFC 8392 defines `aud` as a single StringOrURI, but tokens in the wild follow JWT and also use
  // an array, so both are accepted.
  [RegisteredCwtClaimKey.Audience, z.union([z.string(), z.array(z.string())]).exactOptional()],
  [RegisteredCwtClaimKey.ExpirationTime, zCwtNumericDate.exactOptional()],
  [RegisteredCwtClaimKey.NotBefore, zCwtNumericDate.exactOptional()],
  [RegisteredCwtClaimKey.IssuedAt, zCwtNumericDate.exactOptional()],
  [RegisteredCwtClaimKey.CwtId, zUint8Array.exactOptional()],
] as const

/**
 * Schema for a CWT Claims Set carrying only the registered claims. Additional (application or
 * private use) claims are allowed through untyped.
 */
export const cwtPayloadSchema = typedMap(cwtPayloadClaimEntries, {
  allowAdditionalKeys: true,
  keyLabels: RegisteredCwtClaimKey,
})

export type ExtendedCwtPayloadClaimEntries<Entries extends EntriesBase> = ExtendedEntries<
  typeof cwtPayloadClaimEntries,
  Entries
>

/**
 * Builds a claims schema for a specific CWT type: the registered CWT claims plus the given ones. An
 * entry reusing a registered claim key replaces it, which is how a CWT type makes an inherited claim
 * required or narrows its value.
 *
 * The registered claim names are used in validation errors out of the box. Pass `keyLabels` to name
 * the added claims too — a numeric TypeScript enum can be passed straight in.
 *
 * @example
 * ```ts
 * const statusListCwtPayloadSchema = extendCwtPayloadClaims(
 *   [
 *     // `sub` is optional in the registered claims, but required for a status list
 *     [RegisteredCwtClaimKey.Subject, z.string()],
 *     [StatusListCwtClaimKey.StatusList, z.instanceof(StatusListCbor)],
 *   ] as const,
 *   { keyLabels: StatusListCwtClaimKey }
 * )
 * ```
 */
export function extendCwtPayloadClaims<const Entries extends EntriesBase>(
  entries: Entries,
  {
    keyLabels,
  }: {
    /**
     * Human-readable names for the added claims, merged with the registered CWT claim names. See
     * the `keyLabels` option of `typedMap`.
     */
    keyLabels?: Record<string | number, unknown>
  } = {}
): ReturnType<typeof typedMap<ExtendedCwtPayloadClaimEntries<Entries>>> {
  return typedMap(extendTypedMapEntries(cwtPayloadClaimEntries, entries), {
    allowAdditionalKeys: true,
    keyLabels: { ...RegisteredCwtClaimKey, ...keyLabels },
  })
}

export type CwtPayloadEncodedStructure = z.input<typeof cwtPayloadSchema>
export type CwtPayloadDecodedStructure = z.output<typeof cwtPayloadSchema>

export type CreateCwtPayloadOptions = {
  issuer?: string
  subject?: string
  audience?: string | string[]
  expirationTime?: Date
  notBefore?: Date
  issuedAt?: Date
  cwtId?: Uint8Array

  /**
   * Claims that are not part of the registered CWT claims. Added after the registered claims, in
   * iteration order.
   */
  additionalClaims?: Map<number | string, unknown>
}

/**
 * Builds the claims map for the registered CWT claims from {@link CreateCwtPayloadOptions}, so a CWT
 * type can reuse it while adding its own claims. Claims that were not provided are omitted rather
 * than set to `undefined`, since an explicit `undefined` would be encoded into the CBOR map.
 */
export function cwtPayloadClaimsFromOptions(options: CreateCwtPayloadOptions): Map<number | string, unknown> {
  const claims = new Map<number | string, unknown>()

  if (options.issuer !== undefined) claims.set(RegisteredCwtClaimKey.Issuer, options.issuer)
  if (options.subject !== undefined) claims.set(RegisteredCwtClaimKey.Subject, options.subject)
  if (options.audience !== undefined) claims.set(RegisteredCwtClaimKey.Audience, options.audience)
  if (options.expirationTime !== undefined) {
    claims.set(RegisteredCwtClaimKey.ExpirationTime, dateToSeconds(options.expirationTime))
  }
  if (options.notBefore !== undefined) claims.set(RegisteredCwtClaimKey.NotBefore, dateToSeconds(options.notBefore))
  if (options.issuedAt !== undefined) claims.set(RegisteredCwtClaimKey.IssuedAt, dateToSeconds(options.issuedAt))
  if (options.cwtId !== undefined) claims.set(RegisteredCwtClaimKey.CwtId, options.cwtId)

  for (const [key, value] of options.additionalClaims ?? new Map()) {
    claims.set(key, value)
  }

  return claims
}

// biome-ignore lint/suspicious/noExplicitAny: inferring from an unconstrained TypedMap
type ClaimsSchemaOf<Structure> = Structure extends TypedMap<infer Schema, any> ? Schema : never
// biome-ignore lint/suspicious/noExplicitAny: inferring from an unconstrained TypedMap
type OptionalClaimKeysOf<Structure> = Structure extends TypedMap<any, infer Optional> ? Optional : never

/**
 * The value type of a single claim in a claims map: the schema's type for a claim the CWT type
 * declares (widened with `undefined` when it declares it as optional), and `unknown` for any other
 * claim key, since those are carried through unvalidated.
 */
export type ClaimValue<Structure, Key extends number | string> = Key extends keyof ClaimsSchemaOf<Structure>
  ? Key extends OptionalClaimKeysOf<Structure>
    ? ClaimsSchemaOf<Structure>[Key] | undefined
    : ClaimsSchemaOf<Structure>[Key]
  : unknown

/**
 * The type of a date accessor for a NumericDate claim: `Date` when the CWT type declares the claim
 * as required, and `Date | undefined` otherwise (including for a claim the type does not declare,
 * whose value is `unknown`). This is what makes the inherited date accessors narrow automatically in
 * a subtype that redeclares the claim as required.
 */
export type DateClaimValue<Structure, Key extends number | string> =
  undefined extends ClaimValue<Structure, Key> ? Date | undefined : Date

/**
 * A CWT Claims Set (RFC 8392), with the registered claims typed.
 *
 * A specific CWT type extends this class and overrides {@link encodingSchema} with a schema built by
 * {@link extendCwtPayloadClaims}, passing the resulting decoded structure as `Structure`. The
 * inherited accessors then narrow along with the schema: a claim the subtype declares as required is
 * no longer `undefined`, neither on `claims.get(...)` nor on the accessor for it.
 *
 * @template Structure - The decoded claims map. Defaults to the registered CWT claims.
 */
export class CwtPayload<Structure extends AnyTypedMap = CwtPayloadDecodedStructure> extends CborStructure<
  CwtPayloadEncodedStructure,
  Structure
> {
  // NOTE: widened to `z.ZodType` so a subtype can override it with its own (structurally unrelated)
  // claims schema without breaking static-side assignability.
  public static override get encodingSchema(): z.ZodType {
    return cwtPayloadSchema
  }

  /**
   * The decoded claims map. Typed for the claims this CWT type declares, and open for any other
   * claim key.
   */
  public get claims(): Structure {
    return this.structure
  }

  /**
   * Reads a claim by its key, typed from this CWT type's claims schema. A claim the schema does not
   * declare is returned as `unknown`, as it was carried through unvalidated.
   */
  public getClaim<Key extends number | string>(key: Key): ClaimValue<Structure, Key> {
    return this.structure.get(key) as ClaimValue<Structure, Key>
  }

  /** `iss` (1) */
  public get issuer(): ClaimValue<Structure, RegisteredCwtClaimKey.Issuer> {
    return this.getClaim(RegisteredCwtClaimKey.Issuer)
  }

  /** `sub` (2) */
  public get subject(): ClaimValue<Structure, RegisteredCwtClaimKey.Subject> {
    return this.getClaim(RegisteredCwtClaimKey.Subject)
  }

  /** `aud` (3) */
  public get audience(): ClaimValue<Structure, RegisteredCwtClaimKey.Audience> {
    return this.getClaim(RegisteredCwtClaimKey.Audience)
  }

  /** `exp` (4) */
  public get expirationTime(): DateClaimValue<Structure, RegisteredCwtClaimKey.ExpirationTime> {
    const expirationTime = this.getClaim(RegisteredCwtClaimKey.ExpirationTime)
    return (typeof expirationTime === 'number' ? secondsToDate(expirationTime) : undefined) as DateClaimValue<
      Structure,
      RegisteredCwtClaimKey.ExpirationTime
    >
  }

  /** `nbf` (5) */
  public get notBefore(): DateClaimValue<Structure, RegisteredCwtClaimKey.NotBefore> {
    const notBefore = this.getClaim(RegisteredCwtClaimKey.NotBefore)
    return (typeof notBefore === 'number' ? secondsToDate(notBefore) : undefined) as DateClaimValue<
      Structure,
      RegisteredCwtClaimKey.NotBefore
    >
  }

  /** `iat` (6) */
  public get issuedAt(): DateClaimValue<Structure, RegisteredCwtClaimKey.IssuedAt> {
    const issuedAt = this.getClaim(RegisteredCwtClaimKey.IssuedAt)
    return (typeof issuedAt === 'number' ? secondsToDate(issuedAt) : undefined) as DateClaimValue<
      Structure,
      RegisteredCwtClaimKey.IssuedAt
    >
  }

  /** `cti` (7) */
  public get cwtId(): ClaimValue<Structure, RegisteredCwtClaimKey.CwtId> {
    return this.getClaim(RegisteredCwtClaimKey.CwtId)
  }

  public static create(options: CreateCwtPayloadOptions = {}) {
    return CwtPayload.fromDecodedStructure(TypedMap.fromMap(cwtPayloadClaimsFromOptions(options)))
  }
}

/**
 * A {@link CwtPayload} with any claims schema. Used as a generic bound, because `TypedMap` is
 * invariant in its schema and a subtype's claims map is therefore not assignable to the base one.
 */
// biome-ignore lint/suspicious/noExplicitAny: intentionally unconstrained, used as a generic bound
export type AnyCwtPayload = CwtPayload<any>
