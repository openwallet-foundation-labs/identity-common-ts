import { createCipheriv } from 'node:crypto'
import { getAesBlockEncrypter } from '@owf/crypto'
import { describe, expect, it } from 'vitest'
import {
  createFeistelStatusListIndexAllocator,
  FeistelStatusListIndexAllocator,
  type FeistelStatusListIndexAllocatorContext,
} from '../status-list-index-feistel'

const key = Buffer.from('2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94', 'hex')

const ctx: FeistelStatusListIndexAllocatorContext = {
  encryptBlock: (block) => new Uint8Array(createCipheriv('aes-256-ecb', key, null).setAutoPadding(false).update(block)),
}

const textEncoder = new TextEncoder()

const take = async (allocator: FeistelStatusListIndexAllocator, count: number) => {
  const indices: number[] = []
  for (let i = 0; i < count; i++) indices.push(await allocator.next())
  return indices
}

describe('FeistelStatusListIndexAllocator', () => {
  // Positions already handed out must keep mapping to the same index, or new indices collide with
  // ones already assigned. 1,000,000 and 2^20 share the network and differ only where a result above
  // 1,000,000 is encrypted again.
  it.each([
    { length: 1_000_000, indices: [153753, 570068, 988755, 542398, 959546, 125617, 154603, 230493, 847838, 498807] },
    { length: 2 ** 20, indices: [153753, 570068, 988755, 542398, 1017870, 125617, 154603, 230493, 847838, 498807] },
    { length: 2 ** 20 + 1, indices: [390604, 496013, 204303, 251516, 54619, 295016, 889836, 485692, 445628, 583390] },
    {
      length: 2 ** 32 - 1,
      indices: [
        2987543112, 2435790837, 112314596, 2299367091, 3417124184, 251474971, 1388259544, 3319031383, 525522307,
        3621745279,
      ],
    },
  ])('matches the test vector for a list of $length', async ({ length, indices }) => {
    const allocator = createFeistelStatusListIndexAllocator({ length }, ctx)

    expect(await take(allocator, indices.length)).toEqual(indices)
  })

  // One key with a different tweak per list gives unrelated orders
  it.each([
    {
      uri: 'https://example.com/statuslists/1',
      indices: [194441, 405022, 933438, 234671, 847061, 723, 745148, 535039, 891340, 337336],
    },
    {
      uri: 'https://example.com/statuslists/2',
      indices: [410878, 168580, 881202, 186614, 101015, 918307, 746924, 695236, 1015627, 583103],
    },
  ])('matches the test vector for a list of 2^20 with tweak $uri', async ({ uri, indices }) => {
    const allocator = createFeistelStatusListIndexAllocator({ length: 2 ** 20, tweak: textEncoder.encode(uri) }, ctx)

    expect(await take(allocator, indices.length)).toEqual(indices)
  })

  it('returns distinct indices within the list', async () => {
    const length = 1_000_000
    const indices = await take(createFeistelStatusListIndexAllocator({ length }, ctx), 2000)

    expect(new Set(indices).size).toBe(indices.length)
    expect(indices.every((index) => Number.isInteger(index) && index >= 0 && index < length)).toBe(true)
  })

  it('returns distinct indices for concurrent calls', async () => {
    const allocator = createFeistelStatusListIndexAllocator({ length: 1_000_000 }, ctx)
    const indices = await Promise.all(Array.from({ length: 10 }, () => allocator.next()))

    expect(new Set(indices).size).toBe(10)
    expect(allocator.getState().position).toBe(10)
  })

  it('restores allocation from its state', async () => {
    const allocator = createFeistelStatusListIndexAllocator({ length: 1_000_000 }, ctx)
    await allocator.next()
    const state = allocator.getState()
    const restored = FeistelStatusListIndexAllocator.create(state, ctx)

    expect(state).toEqual({ length: 1_000_000, position: 1 })
    expect(await restored.next()).toBe(await allocator.next())
    expect(restored.remaining()).toBe(999_998)
  })

  it('restores the tweak from its state', async () => {
    const tweak = textEncoder.encode('https://example.com/statuslists/1')
    const allocator = createFeistelStatusListIndexAllocator({ length: 2 ** 20, tweak }, ctx)
    await allocator.next()
    const state = allocator.getState()
    const restored = FeistelStatusListIndexAllocator.create(state, ctx)

    expect(state).toEqual({ length: 2 ** 20, position: 1, tweak })
    expect(await restored.next()).toBe(405022)
  })

  it('throws when exhausted', async () => {
    const allocator = createFeistelStatusListIndexAllocator({ length: 1_000_000, position: 999_999 }, ctx)
    await allocator.next()

    await expect(allocator.next()).rejects.toThrow('No status list indices remain')
  })

  it('rejects invalid input', () => {
    expect(() => createFeistelStatusListIndexAllocator({ length: 999_999 }, ctx)).toThrow('1,000,000')
    expect(() => createFeistelStatusListIndexAllocator({ length: 2 ** 32 }, ctx)).toThrow('2^32 - 1')
    expect(() => createFeistelStatusListIndexAllocator({ length: 1_000_000, position: 1_000_001 }, ctx)).toThrow(
      'position'
    )
    expect(() => createFeistelStatusListIndexAllocator({ length: 1_000_000, position: -1 }, ctx)).toThrow('position')
  })

  it('accepts the async AES block encrypter from @owf/crypto', async () => {
    const allocator = createFeistelStatusListIndexAllocator(
      { length: 1_000_000 },
      { encryptBlock: await getAesBlockEncrypter(key) }
    )

    expect(await take(allocator, 3)).toEqual([153753, 570068, 988755])
  })
})
