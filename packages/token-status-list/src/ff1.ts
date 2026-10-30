import type { OrPromise } from '@owf/identity-common'
import { SLException } from './status-list-exception'

/** Encrypts one 16-byte block with AES under the caller's key (AES-ECB without padding). */
export type EncryptBlock = (block: Uint8Array<ArrayBuffer>) => OrPromise<Uint8Array>

export interface Ff1Options {
  radix: number
  tweak?: Uint8Array
  encryptBlock: EncryptBlock
}

const BLOCK_SIZE = 16
const ROUNDS = 10
const MIN_DOMAIN_SIZE = 1_000_000n

/**
 * FF1.Encrypt from NIST SP 800-38G Rev. 1 (second public draft, Algorithm 5). The numeral string of
 * `length` numerals is passed as the number it represents, most significant numeral first.
 */
export async function ff1Encrypt(value: bigint, length: number, options: Ff1Options): Promise<bigint> {
  const { radix, tweak = new Uint8Array(), encryptBlock } = options
  const radixBig = BigInt(radix)

  if (!Number.isInteger(radix) || radix < 2 || radix > 2 ** 16) {
    throw new SLException('FF1 radix must be between 2 and 2^16')
  }
  if (!Number.isInteger(length) || length < 2 || length >= 2 ** 32 || radixBig ** BigInt(length) < MIN_DOMAIN_SIZE) {
    throw new SLException('FF1 needs at least 2 numerals and a domain of at least 1,000,000 values')
  }
  if (value < 0n || value >= radixBig ** BigInt(length)) {
    throw new SLException('FF1 input is outside the domain')
  }

  const u = Math.floor(length / 2)
  const v = length - u
  const radixU = radixBig ** BigInt(u)
  const radixV = radixBig ** BigInt(v)
  let a = value / radixV
  let b = value % radixV

  const byteLength = Math.ceil((radixV - 1n).toString(2).length / 8)
  const outputLength = 4 * Math.ceil(byteLength / 4) + 4
  const t = tweak.length

  const p = new Uint8Array(BLOCK_SIZE)
  p.set([1, 2, 1])
  p.set(toBytes(BigInt(radix), 3), 3)
  p.set([10, u % 256], 6)
  p.set(toBytes(BigInt(length), 4), 8)
  p.set(toBytes(BigInt(t), 4), 12)

  // P || Q is P || T || [0]^padding || [round] || [B]. Everything before the round is the same in
  // each round, so the CBC-MAC over its whole blocks is computed once.
  const padding = (((-t - byteLength - 1) % BLOCK_SIZE) + BLOCK_SIZE) % BLOCK_SIZE
  const prefix = new Uint8Array(BLOCK_SIZE + t + padding)
  prefix.set(p)
  prefix.set(tweak, BLOCK_SIZE)
  const fixedLength = prefix.length - (prefix.length % BLOCK_SIZE)
  const fixedMac = await cbcMac(new Uint8Array(BLOCK_SIZE), prefix.subarray(0, fixedLength), encryptBlock)

  const rest = new Uint8Array(prefix.length - fixedLength + 1 + byteLength)
  const roundOffset = prefix.length - fixedLength
  rest.set(prefix.subarray(fixedLength))

  for (let round = 0; round < ROUNDS; round++) {
    rest[roundOffset] = round
    rest.set(toBytes(b, byteLength), roundOffset + 1)

    const r = await cbcMac(fixedMac, rest, encryptBlock)
    const s = new Uint8Array(Math.ceil(outputLength / BLOCK_SIZE) * BLOCK_SIZE)
    s.set(r)
    for (let block = 1; block * BLOCK_SIZE < outputLength; block++) {
      s.set(await cipher(xor(r, toBytes(BigInt(block), BLOCK_SIZE)), encryptBlock), block * BLOCK_SIZE)
    }

    const y = fromBytes(s.subarray(0, outputLength))
    const c = (a + y) % (round % 2 === 0 ? radixU : radixV)
    a = b
    b = c
  }

  return a * radixV + b
}

/** Continues a CBC-MAC from `state` over `input`, whose length is a multiple of the block size. */
async function cbcMac(state: Uint8Array, input: Uint8Array, encryptBlock: EncryptBlock): Promise<Uint8Array> {
  let y = state
  for (let start = 0; start < input.length; start += BLOCK_SIZE) {
    y = await cipher(xor(y, input.subarray(start, start + BLOCK_SIZE)), encryptBlock)
  }
  return y
}

async function cipher(block: Uint8Array<ArrayBuffer>, encryptBlock: EncryptBlock): Promise<Uint8Array> {
  const output = await encryptBlock(block)
  if (output.length !== BLOCK_SIZE) {
    throw new SLException(`encryptBlock returned ${output.length} bytes, expected ${BLOCK_SIZE}`)
  }
  return new Uint8Array(output)
}

function xor(left: Uint8Array, right: Uint8Array): Uint8Array<ArrayBuffer> {
  return left.map((byte, index) => byte ^ right[index])
}

function toBytes(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length)
  let remaining = value
  for (let index = length - 1; index >= 0; index--) {
    bytes[index] = Number(remaining & 0xffn)
    remaining >>= 8n
  }
  return bytes
}

function fromBytes(bytes: Uint8Array): bigint {
  let value = 0n
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte)
  }
  return value
}
