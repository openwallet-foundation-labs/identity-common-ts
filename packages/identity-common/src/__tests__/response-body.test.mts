import { describe, expect, it, vi } from 'vitest'
import { IdentityCommonError } from '../../src'
import { readResponseBodyAtMost } from '../response-body'

/** A body that streams `chunkCount` chunks of `chunkSize` bytes, counting the chunks it was asked for. */
const streamedBody = (chunkSize: number, chunkCount = Number.POSITIVE_INFINITY) => {
  const stream = { pulled: 0, cancelled: false }
  const body = new ReadableStream<Uint8Array>(
    {
      pull: (controller) => {
        if (stream.pulled === chunkCount) return controller.close()
        stream.pulled++
        controller.enqueue(new Uint8Array(chunkSize).fill(stream.pulled))
      },
      cancel: () => {
        stream.cancelled = true
      },
    },
    { highWaterMark: 0 }
  )
  return { stream, body }
}

describe('readResponseBodyAtMost', () => {
  it('reads a body of maxBytes, in the order of its chunks', async () => {
    const { body } = streamedBody(2, 3)

    await expect(readResponseBodyAtMost(new Response(body), 6)).resolves.toEqual(new Uint8Array([1, 1, 2, 2, 3, 3]))
  })

  it('rejects a response by its Content-Length, before reading the body', async () => {
    const { stream, body } = streamedBody(1024)

    await expect(
      readResponseBodyAtMost(new Response(body, { headers: { 'Content-Length': '4097' } }), 4096)
    ).rejects.toThrow(new IdentityCommonError('The response is larger than the maximum of 4096 bytes'))
    expect(stream.pulled).toBe(0)
    expect(stream.cancelled).toBe(true)
  })

  it('stops reading a body without Content-Length once it is larger than maxBytes', async () => {
    const { stream, body } = streamedBody(1024)

    await expect(readResponseBodyAtMost(new Response(body), 4096)).rejects.toThrow(
      'The response is larger than the maximum of 4096 bytes'
    )
    expect(stream.pulled).toBe(5)
    expect(stream.cancelled).toBe(true)
  })

  it.each([Number.NaN, -1])('rejects a maxBytes of %s before reading the body', async (maxBytes) => {
    const { stream, body } = streamedBody(1024)

    await expect(readResponseBodyAtMost(new Response(body), maxBytes)).rejects.toThrow(
      new IdentityCommonError(`The maximum size of a response must be a number of 0 or more, but is ${maxBytes}`)
    )
    expect(stream.pulled).toBe(0)
  })

  // The fetch of React Native has no body stream
  it('reads a body without a stream whole, and rejects it when it is larger than maxBytes', async () => {
    const withoutStream = (body: Uint8Array<ArrayBuffer>) => {
      const response = new Response(body)
      Object.defineProperty(response, 'body', { value: null })
      return { response, arrayBuffer: vi.spyOn(response, 'arrayBuffer') }
    }

    const small = withoutStream(new Uint8Array(4096))
    await expect(readResponseBodyAtMost(small.response, 4096)).resolves.toEqual(new Uint8Array(4096))
    expect(small.arrayBuffer).toHaveBeenCalled()

    await expect(readResponseBodyAtMost(withoutStream(new Uint8Array(4097)).response, 4096)).rejects.toThrow(
      'The response is larger than the maximum of 4096 bytes'
    )
  })
})
