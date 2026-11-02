import { createHashMapping, getSdAlgAndPayload, unpack } from './decode'
import { createDecoy } from './decoy'
import { Jwt } from './jwt'
import { KbJwt } from './kbjwt'
import { transformPresentationFrame } from './present'
import {
  type DisclosureFrame,
  encodePathSegment,
  type Hasher,
  type HasherAndAlg,
  type KbJwtHeader,
  type KbJwtPayload,
  type PresentationFrame,
  type SaltGenerator,
  SD_DECOY,
  SD_DIGEST,
  SD_LIST_KEY,
  SD_SEPARATOR,
  type SdJwtCompact,
} from './types'
import { Disclosure, SdJwtError } from './utils'

const createDisclosureSalt = async (saltGenerator: SaltGenerator, seenSalts: Set<string>) => {
  const salt = await saltGenerator(16)
  if (typeof salt !== 'string') {
    throw new SdJwtError('SaltGenerator must return a string')
  }
  if (seenSalts.has(salt)) {
    throw new SdJwtError('Duplicate disclosure salt detected')
  }
  seenSalts.add(salt)
  return salt
}

const addDisclosureDigest = (digest: string, seenDigests: Set<string>) => {
  if (seenDigests.has(digest)) {
    throw new SdJwtError('Duplicate disclosure digest detected')
  }
  seenDigests.add(digest)
}

export type SdJwtData<
  Header extends Record<string, unknown>,
  Payload extends Record<string, unknown>,
  KbHeader extends KbJwtHeader = KbJwtHeader,
  KbPayload extends KbJwtPayload = KbJwtPayload,
> = {
  jwt?: Jwt<Header, Payload>
  disclosures?: Array<Disclosure>
  kbJwt?: KbJwt<KbHeader, KbPayload>
}

export class SdJwt<
  Header extends Record<string, unknown> = Record<string, unknown>,
  Payload extends Record<string, unknown> = Record<string, unknown>,
  KbHeader extends KbJwtHeader = KbJwtHeader,
  KbPayload extends KbJwtPayload = KbJwtPayload,
> {
  public jwt?: Jwt<Header, Payload>
  public disclosures?: Array<Disclosure>
  public kbJwt?: KbJwt<KbHeader, KbPayload>

  constructor(data?: SdJwtData<Header, Payload, KbHeader, KbPayload>) {
    this.jwt = data?.jwt
    this.disclosures = data?.disclosures
    this.kbJwt = data?.kbJwt
  }

  public static async decodeSdJwt<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
    KbHeader extends KbJwtHeader = KbJwtHeader,
    KbPayload extends KbJwtPayload = KbJwtPayload,
  >(
    sdjwt: SdJwtCompact,
    hasher: Hasher
  ): Promise<{
    jwt: Jwt<Header, Payload>
    disclosures: Array<Disclosure>
    kbJwt?: KbJwt<KbHeader, KbPayload>
  }> {
    const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR)
    if (encodedDisclosures.length === 0) {
      throw new SdJwtError('Invalid SD-JWT: missing SD-JWT separator')
    }
    const jwt = Jwt.fromEncode<Header, Payload>(encodedJwt)

    if (!jwt.payload) {
      throw new Error('Payload is undefined on the JWT. Invalid state reached')
    }

    const encodedKeyBindingJwt = encodedDisclosures.pop()
    const kbJwt = encodedKeyBindingJwt ? KbJwt.fromKbEncode<KbHeader, KbPayload>(encodedKeyBindingJwt) : undefined

    const { _sd_alg } = getSdAlgAndPayload(jwt.payload)

    const disclosures = await Promise.all(
      encodedDisclosures.map((ed) => Disclosure.fromEncode(ed, { alg: _sd_alg, hasher }))
    )

    return {
      jwt,
      disclosures,
      kbJwt,
    }
  }

  public static async extractJwt<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
  >(encodedSdJwt: SdJwtCompact): Promise<Jwt<Header, Payload>> {
    const [encodedJwt, ..._encodedDisclosures] = encodedSdJwt.split(SD_SEPARATOR)

    return Jwt.fromEncode(encodedJwt)
  }

  public static async fromEncode<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
    KbHeader extends KbJwtHeader = KbJwtHeader,
    KbPayload extends KbJwtPayload = KbJwtPayload,
  >(encodedSdJwt: SdJwtCompact, hasher: Hasher): Promise<SdJwt<Header, Payload, KbHeader, KbPayload>> {
    const { jwt, disclosures, kbJwt } = await SdJwt.decodeSdJwt<Header, Payload, KbHeader, KbPayload>(
      encodedSdJwt,
      hasher
    )

    return new SdJwt<Header, Payload, KbHeader, KbPayload>({
      jwt,
      disclosures,
      kbJwt,
    })
  }

  public async present<T extends Record<string, unknown>>(
    presentFrame: PresentationFrame<T> | undefined,
    hasher: Hasher
  ): Promise<SdJwtCompact> {
    const disclosures = await this.getPresentDisclosures(presentFrame, hasher)
    const presentSdJwt = new SdJwt({
      jwt: this.jwt,
      disclosures,
      kbJwt: this.kbJwt,
    })
    return presentSdJwt.encodeSdJwt()
  }

  public async getPresentDisclosures<T extends Record<string, unknown>>(
    presentFrame: PresentationFrame<T> | undefined,
    hasher: Hasher
  ): Promise<Disclosure<unknown>[]> {
    if (!this.jwt?.payload || !this.disclosures) {
      throw new SdJwtError('Invalid sd-jwt: jwt or disclosures is missing')
    }
    const { _sd_alg: alg } = getSdAlgAndPayload(this.jwt.payload)
    const hash = { alg, hasher }
    const hashmap = await createHashMapping(this.disclosures, hash)
    const { disclosureKeymap } = await unpack(this.jwt.payload, this.disclosures, hasher)

    const keys = presentFrame ? transformPresentationFrame(presentFrame) : await this.presentableKeys(hasher)
    const disclosures = keys.map((k) => hashmap[disclosureKeymap[k]]).filter((d) => d !== undefined)
    return disclosures
  }

  public encodeSdJwt(): SdJwtCompact {
    const data: string[] = []

    if (!this.jwt) {
      throw new SdJwtError('Invalid sd-jwt: jwt is missing')
    }

    const encodedJwt = this.jwt.encodeJwt()
    data.push(encodedJwt)

    if (this.disclosures && this.disclosures.length > 0) {
      const encodeddisclosures = this.disclosures.map((dc) => dc.encode()).join(SD_SEPARATOR)
      data.push(encodeddisclosures)
    }

    data.push(this.kbJwt ? this.kbJwt.encodeJwt() : '')
    return data.join(SD_SEPARATOR)
  }

  public async keys(hasher: Hasher): Promise<string[]> {
    return listKeys(await this.getClaims(hasher)).sort()
  }

  public async presentableKeys(hasher: Hasher): Promise<string[]> {
    if (!this.jwt?.payload || !this.disclosures) {
      throw new SdJwtError('Invalid sd-jwt: jwt or disclosures is missing')
    }
    const { disclosureKeymap } = await unpack(this.jwt?.payload, this.disclosures, hasher)
    return Object.keys(disclosureKeymap).sort()
  }

  public async getClaims<T = Payload>(hasher: Hasher): Promise<T> {
    if (!this.jwt?.payload || !this.disclosures) {
      throw new SdJwtError('Invalid sd-jwt: jwt or disclosures is missing')
    }
    const { unpackedObj } = await unpack(this.jwt.payload, this.disclosures, hasher)
    return unpackedObj as T
  }
}

export const listKeys = (obj: Record<string, unknown>, prefix = '') => {
  const keys: string[] = []
  for (const key in obj) {
    if (obj[key] === undefined) continue
    const escapedKey = encodePathSegment(key)
    const newKey = prefix ? `${prefix}.${escapedKey}` : escapedKey
    keys.push(newKey)

    const value = obj[key]
    if (value && typeof value === 'object') {
      keys.push(...listKeys(value as Record<string, unknown>, newKey))
    }
  }
  return keys
}

export const pack = async <T extends Record<string, unknown>>(
  claims: T,
  disclosureFrame: DisclosureFrame<T> | undefined,
  hash: HasherAndAlg,
  saltGenerator: SaltGenerator,
  seenSalts = new Set<string>(),
  seenDigests = new Set<string>()
): Promise<{
  packedClaims: Record<string, unknown> | Array<Record<string, unknown>>
  disclosures: Array<Disclosure>
}> => {
  if (!disclosureFrame) {
    return {
      packedClaims: claims,
      disclosures: [],
    }
  }

  const sd = disclosureFrame[SD_DIGEST] ?? []
  const decoyCount = disclosureFrame[SD_DECOY] ?? 0

  if (Array.isArray(claims)) {
    const packedClaims: Array<Record<typeof SD_LIST_KEY, string>> = []
    const disclosures: Array<Disclosure> = []
    const recursivePackedClaims: Record<number, unknown> = {}

    for (const key in disclosureFrame) {
      if (key !== SD_DIGEST) {
        const idx = Number.parseInt(key, 10)
        const packed = await pack<Record<string, unknown>>(
          claims[idx],
          disclosureFrame[idx] as DisclosureFrame<Record<string, unknown>> | undefined,
          hash,
          saltGenerator,
          seenSalts,
          seenDigests
        )
        recursivePackedClaims[idx] = packed.packedClaims
        disclosures.push(...packed.disclosures)
      }
    }

    for (let i = 0; i < claims.length; i++) {
      const claim = recursivePackedClaims[i] ? recursivePackedClaims[i] : claims[i]
      /** This part is set discloure for array items.
       *  The example of disclosureFrame of an Array is
       *
       *  const claims = {
       *    array: ['a', 'b', 'c']
       *  }
       *
       *  diclosureFrame: DisclosureFrame<typeof claims> = {
       *    array: {
       *      _sd: [0, 2]
       *    }
       *  }
       *
       *  It means that we want to disclose the first and the third item of the array
       *
       *  So If the index `i` is in the disclosure list(sd), then we create a disclosure for the claim
       */
      // @ts-expect-error
      if (sd.includes(i)) {
        const salt = await createDisclosureSalt(saltGenerator, seenSalts)
        const disclosure = new Disclosure([salt, claim])
        const digest = await disclosure.digest(hash)
        addDisclosureDigest(digest, seenDigests)
        packedClaims.push({ [SD_LIST_KEY]: digest })
        disclosures.push(disclosure)
      } else {
        packedClaims.push(claim)
      }
    }
    for (let j = 0; j < decoyCount; j++) {
      const decoyDigest = await createDecoy(hash, saltGenerator)
      addDisclosureDigest(decoyDigest, seenDigests)
      packedClaims.push({ [SD_LIST_KEY]: decoyDigest })
    }
    return { packedClaims, disclosures }
  }

  const packedClaims: Record<string, unknown> = {}
  const disclosures: Array<Disclosure> = []
  const recursivePackedClaims: Record<string, unknown> = {}

  for (const key in disclosureFrame) {
    if (key !== SD_DIGEST) {
      const packed = await pack(
        // @ts-expect-error
        claims[key],
        disclosureFrame[key],
        hash,
        saltGenerator,
        seenSalts,
        seenDigests
      )
      recursivePackedClaims[key] = packed.packedClaims
      disclosures.push(...packed.disclosures)
    }
  }

  const _sd: string[] = []

  for (const key in claims) {
    const claim = recursivePackedClaims[key] ? recursivePackedClaims[key] : claims[key]
    if (sd.includes(key)) {
      const salt = await createDisclosureSalt(saltGenerator, seenSalts)
      const disclosure = new Disclosure([salt, key, claim])
      const digest = await disclosure.digest(hash)
      addDisclosureDigest(digest, seenDigests)

      _sd.push(digest)
      disclosures.push(disclosure)
    } else {
      packedClaims[key] = claim
    }
  }

  for (let j = 0; j < decoyCount; j++) {
    const decoyDigest = await createDecoy(hash, saltGenerator)
    addDisclosureDigest(decoyDigest, seenDigests)
    _sd.push(decoyDigest)
  }

  if (_sd.length > 0) {
    packedClaims[SD_DIGEST] = _sd.sort()
  }
  return { packedClaims, disclosures }
}
