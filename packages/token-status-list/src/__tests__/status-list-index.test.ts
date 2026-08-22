import { describe, expect, it } from 'vitest'
import { createStatusListIndexAllocator, StatusListIndexAllocator } from '../status-list-index'

describe('StatusListIndexAllocator', () => {
  const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])

  it('returns a deterministic permutation of all indices', async () => {
    const first = await createStatusListIndexAllocator(100, seed)
    const second = await createStatusListIndexAllocator(100, seed)
    const firstIndices = Array.from({ length: 100 }, () => first.next())
    const secondIndices = Array.from({ length: 100 }, () => second.next())

    expect(firstIndices).toEqual(secondIndices)
    expect(new Set(firstIndices).size).toBe(100)
    expect(firstIndices.sort((left, right) => left - right)).toEqual(Array.from({ length: 100 }, (_, i) => i))
  })

  it('restores allocation from its state', async () => {
    const allocator = await createStatusListIndexAllocator(10, seed)
    const firstIndex = allocator.next()
    const state = allocator.getState()
    const restored = await StatusListIndexAllocator.create(state.length, state.seed, state.position)

    expect(firstIndex).not.toBe(restored.next())
    expect(restored.remaining()).toBe(8)
  })

  it('throws when exhausted', async () => {
    const allocator = await createStatusListIndexAllocator(1, seed)
    allocator.next()

    expect(() => allocator.next()).toThrow('No status list indices remain')
  })

  it('rejects invalid input', async () => {
    await expect(createStatusListIndexAllocator(0, seed)).rejects.toThrow()
    await expect(createStatusListIndexAllocator(1, new Uint8Array())).rejects.toThrow()
    await expect(createStatusListIndexAllocator(1, seed, 2)).rejects.toThrow()
  })
})
