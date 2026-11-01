import { type EncryptBlock, ff1Encrypt } from './ff1'
import { SLException } from './status-list-exception'

/** NIST requires FF1's domain to hold at least 1,000,000 values. */
const MIN_LENGTH = 1_000_000

export interface FeistelStatusListIndexAllocatorState {
  length: number
  position: number
  tweak?: Uint8Array
}

export interface FeistelStatusListIndexAllocatorOptions {
  /** Number of indices in the status list, at least 1,000,000. */
  length: number
  /** Number of indices already handed out. Defaults to 0. */
  position?: number
  /**
   * FF1 tweak that makes the order unique to this list, so one key can serve several lists, for
   * example the encoded status list URI. It doesn't have to be secret, but it must be unique among the
   * lists that share the key and stay the same for the life of the list.
   */
  tweak?: Uint8Array
}

/**
 * AES callback the indices are derived from. This package never reaches for a global Web Crypto
 * implementation, and the key never leaves the callback, so it can be a non-extractable key or live
 * in a key management service.
 */
export interface FeistelStatusListIndexAllocatorContext {
  /** Encrypts one 16-byte block with AES under the private key (AES-ECB without padding). */
  encryptBlock: EncryptBlock
}

/**
 * Assigns each index once by encrypting the position with FF1, NIST's Feistel-based format-preserving
 * encryption (SP 800-38G). Nothing is computed up front, so creating or restoring an allocator is free.
 */
export class FeistelStatusListIndexAllocator {
  private readonly length: number
  private readonly bits: number
  private readonly tweak?: Uint8Array
  private readonly encryptBlock: EncryptBlock
  private position: number

  private constructor({ length, position, tweak }: FeistelStatusListIndexAllocatorState, encryptBlock: EncryptBlock) {
    this.length = length
    this.bits = (length - 1).toString(2).length
    this.tweak = tweak && new Uint8Array(tweak)
    this.encryptBlock = encryptBlock
    this.position = position
  }

  static create(
    { length, position = 0, tweak }: FeistelStatusListIndexAllocatorOptions,
    ctx: FeistelStatusListIndexAllocatorContext
  ): FeistelStatusListIndexAllocator {
    if (!Number.isSafeInteger(length) || length < MIN_LENGTH || length > 0xffffffff) {
      throw new SLException('length must be an integer between 1,000,000 and 2^32 - 1')
    }
    if (!Number.isSafeInteger(position) || position < 0 || position > length) {
      throw new SLException('position must be between 0 and length')
    }

    return new FeistelStatusListIndexAllocator({ length, position, tweak }, ctx.encryptBlock)
  }

  async next(): Promise<number> {
    if (this.position >= this.length) {
      throw new SLException('No status list indices remain')
    }

    // Claimed before encrypting, so concurrent calls never get the same position
    let value = BigInt(this.position++)
    const options = { radix: 2, tweak: this.tweak, encryptBlock: this.encryptBlock }

    // FF1 permutes [0, 2^bits). A result outside the list is encrypted again (cycle walking), which
    // ends within the list because the position itself is.
    do {
      value = await ff1Encrypt(value, this.bits, options)
    } while (value >= this.length)

    return Number(value)
  }

  remaining(): number {
    return this.length - this.position
  }

  getState(): FeistelStatusListIndexAllocatorState {
    return {
      length: this.length,
      position: this.position,
      ...(this.tweak && { tweak: new Uint8Array(this.tweak) }),
    }
  }
}

export function createFeistelStatusListIndexAllocator(
  options: FeistelStatusListIndexAllocatorOptions,
  ctx: FeistelStatusListIndexAllocatorContext
): FeistelStatusListIndexAllocator {
  return FeistelStatusListIndexAllocator.create(options, ctx)
}
