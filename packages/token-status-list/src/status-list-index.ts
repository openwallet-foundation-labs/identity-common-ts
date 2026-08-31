import type { Hasher } from '@owf/identity-common'
import { SLException } from './status-list-exception'

const UINT32_RANGE = 0x100000000

/** The permutation is defined over SHA-256 of `seed || counter`. */
const SEED_HASH_ALGORITHM = 'sha-256'

export interface StatusListIndexAllocatorState {
  length: number
  position: number
  seed: Uint8Array
}

export interface StatusListIndexAllocatorOptions {
  /** Number of indices in the status list. */
  length: number
  /** Private seed the permutation is derived from. */
  seed: Uint8Array
  /** Number of indices already handed out. Defaults to 0. */
  position?: number
}

/**
 * Hashing callback used to expand the seed. This package never reaches for a
 * global Web Crypto implementation — the caller decides which engine computes
 * the digest.
 *
 * The permutation is only reproducible when `hasher` computes SHA-256, so the
 * same seed keeps allocating the same indices across restarts and processes.
 */
export interface StatusListIndexAllocatorContext {
  hasher: Hasher
}

class SeededRandom {
  private readonly seed: Uint8Array
  private readonly hasher: Hasher
  private counter = 0
  private buffer: Uint8Array = new Uint8Array(0)
  private bufferOffset = 0

  constructor(seed: Uint8Array, hasher: Hasher) {
    this.seed = new Uint8Array(seed)
    this.hasher = hasher
  }

  async nextInt(maxExclusive: number): Promise<number> {
    const limit = UINT32_RANGE - (UINT32_RANGE % maxExclusive)
    let value: number

    do {
      value = await this.nextUint32()
    } while (value >= limit)

    return value % maxExclusive
  }

  private async nextUint32(): Promise<number> {
    if (this.bufferOffset + 4 > this.buffer.length) {
      const input = new Uint8Array(this.seed.length + 4)
      input.set(this.seed)
      new DataView(input.buffer).setUint32(this.seed.length, this.counter++)
      const digest = await this.hasher(input.buffer as ArrayBuffer, SEED_HASH_ALGORITHM)
      // Guard against a hasher that returns too little to make progress on:
      // without this the do/while in nextInt would spin forever.
      if (digest.length < 4) {
        throw new SLException(`hasher returned ${digest.length} bytes for ${SEED_HASH_ALGORITHM}, expected at least 4`)
      }
      this.buffer = digest
      this.bufferOffset = 0
    }

    const value = new DataView(this.buffer.buffer, this.buffer.byteOffset + this.bufferOffset).getUint32(0)
    this.bufferOffset += 4
    return value
  }
}

export class StatusListIndexAllocator {
  private readonly indices: Uint32Array
  private readonly seed: Uint8Array
  private position: number

  private constructor(indices: Uint32Array, seed: Uint8Array, position: number) {
    this.indices = indices
    this.seed = new Uint8Array(seed)
    this.position = position
  }

  static async create(
    { length, seed, position = 0 }: StatusListIndexAllocatorOptions,
    ctx: StatusListIndexAllocatorContext
  ): Promise<StatusListIndexAllocator> {
    validateLength(length)
    validateSeed(seed)
    validatePosition(position, length)

    const indices = new Uint32Array(length)
    for (let index = 0; index < length; index++) {
      indices[index] = index
    }

    const random = new SeededRandom(seed, ctx.hasher)
    for (let index = length - 1; index > 0; index--) {
      const swapIndex = await random.nextInt(index + 1)
      const value = indices[index]
      indices[index] = indices[swapIndex]
      indices[swapIndex] = value
    }

    return new StatusListIndexAllocator(indices, seed, position)
  }

  next(): number {
    if (this.position >= this.indices.length) {
      throw new SLException('No status list indices remain')
    }

    return this.indices[this.position++]
  }

  remaining(): number {
    return this.indices.length - this.position
  }

  getState(): StatusListIndexAllocatorState {
    return {
      length: this.indices.length,
      position: this.position,
      seed: new Uint8Array(this.seed),
    }
  }
}

export async function createStatusListIndexAllocator(
  options: StatusListIndexAllocatorOptions,
  ctx: StatusListIndexAllocatorContext
): Promise<StatusListIndexAllocator> {
  return StatusListIndexAllocator.create(options, ctx)
}

function validateLength(length: number): void {
  if (!Number.isSafeInteger(length) || length <= 0 || length > 0xffffffff) {
    throw new SLException('length must be a positive safe integer no greater than 2^32 - 1')
  }
}

function validatePosition(position: number, length: number): void {
  if (!Number.isSafeInteger(position) || position < 0 || position > length) {
    throw new SLException('position must be between 0 and length')
  }
}

function validateSeed(seed: Uint8Array): void {
  if (seed.length === 0) {
    throw new SLException('seed must not be empty')
  }
}
