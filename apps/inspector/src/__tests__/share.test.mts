import { describe, expect, it } from 'vitest'
import { compress, decompress, fromFragment, toFragment } from '../share'

describe('sharing in the fragment', () => {
  it('compresses a value and reads it back', async () => {
    const text = `<TrustServiceStatusList>${'<x>ä</x>'.repeat(200)}</TrustServiceStatusList>`
    const compressed = await compress(text)
    expect(compressed).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(compressed.length).toBeLessThan(text.length / 4)
    await expect(decompress(compressed)).resolves.toBe(text)
  })

  it('reads a value that is not compressed as it is', async () => {
    const jwt = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln'
    await expect(decompress(jwt)).resolves.toBe(jwt)
    await expect(decompress('a0b1c2')).resolves.toBe('a0b1c2')
  })

  it('writes and reads the values of a page', async () => {
    const fragment = await toFragment([
      { name: 'doc', value: 'eyJ…~', compress: true },
      { name: 'nonce', value: 'n 0&S6', compress: false },
      { name: 'aud', value: '', compress: false },
    ])
    expect(fragment).not.toContain('aud')
    const values = await fromFragment(`#${fragment}`, new Set(['doc']))
    expect(Object.fromEntries(values)).toEqual({ doc: 'eyJ…~', nonce: 'n 0&S6' })
  })
})
