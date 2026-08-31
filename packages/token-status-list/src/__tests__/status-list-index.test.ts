import { sha256 } from '@noble/hashes/sha2.js'
import { describe, expect, it } from 'vitest'
import {
  createStatusListIndexAllocator,
  StatusListIndexAllocator,
  type StatusListIndexAllocatorContext,
} from '../status-list-index'

const textEncoder = new TextEncoder()

const ctx: StatusListIndexAllocatorContext = {
  hasher: (data) => sha256(typeof data === 'string' ? textEncoder.encode(data) : new Uint8Array(data)),
}

describe('StatusListIndexAllocator', () => {
  const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])

  it('returns a deterministic permutation of all indices', async () => {
    const first = await createStatusListIndexAllocator({ length: 100, seed }, ctx)
    const second = await createStatusListIndexAllocator({ length: 100, seed }, ctx)
    const firstIndices = Array.from({ length: 100 }, () => first.next())
    const secondIndices = Array.from({ length: 100 }, () => second.next())

    expect(firstIndices).toEqual(secondIndices)
    expect(new Set(firstIndices).size).toBe(100)
    expect(firstIndices.sort((left, right) => left - right)).toEqual(Array.from({ length: 100 }, (_, i) => i))
  })

  it('restores allocation from its state', async () => {
    const allocator = await createStatusListIndexAllocator({ length: 10, seed }, ctx)
    const firstIndex = allocator.next()
    const state = allocator.getState()
    const restored = await StatusListIndexAllocator.create(state, ctx)

    expect(firstIndex).not.toBe(restored.next())
    expect(restored.remaining()).toBe(8)
  })

  it('throws when exhausted', async () => {
    const allocator = await createStatusListIndexAllocator({ length: 1, seed }, ctx)
    allocator.next()

    expect(() => allocator.next()).toThrow('No status list indices remain')
  })

  it('rejects invalid input', async () => {
    await expect(createStatusListIndexAllocator({ length: 0, seed }, ctx)).rejects.toThrow()
    await expect(createStatusListIndexAllocator({ length: 1, seed: new Uint8Array() }, ctx)).rejects.toThrow()
    await expect(createStatusListIndexAllocator({ length: 1, seed, position: 2 }, ctx)).rejects.toThrow()
  })

  it('uses the supplied hasher rather than a global crypto implementation', async () => {
    const algorithms: string[] = []
    const recording: StatusListIndexAllocatorContext = {
      hasher: (data, alg) => {
        algorithms.push(alg)
        return ctx.hasher(data, alg)
      },
    }

    await createStatusListIndexAllocator({ length: 100, seed }, recording)

    expect(algorithms.length).toBeGreaterThan(0)
    expect(new Set(algorithms)).toEqual(new Set(['sha-256']))
  })

  it('rejects a hasher that returns too few bytes to make progress', async () => {
    await expect(
      createStatusListIndexAllocator({ length: 10, seed }, { hasher: () => new Uint8Array([1, 2]) })
    ).rejects.toThrow('expected at least 4')
  })
})
