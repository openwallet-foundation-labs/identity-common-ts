import { IdentityCommonError } from './identity-common-error'

/**
 * Read the body of a fetch `response`, but stop with an error once it is larger than `maxBytes`, so that a large
 * response is not read into memory whole.
 *
 * A `Content-Length` above `maxBytes` is rejected before the body is read. A body stream is counted as it is read,
 * and cancelled once it is larger. Where fetch has no body stream, the body is read whole and checked afterwards.
 * The fetch of React Native without Expo has none, so use a fetch that streams the body there, such as the one of
 * Expo (`expo/fetch`) or `react-native-nitro-fetch`.
 *
 * @returns The body, in a new array over a buffer of its own.
 * @throws IdentityCommonError if `maxBytes` is not a number of 0 or more, or the response is larger than `maxBytes`.
 */
export async function readResponseBodyAtMost(response: Response, maxBytes: number): Promise<Uint8Array<ArrayBuffer>> {
  if (Number.isNaN(maxBytes) || maxBytes < 0) {
    throw new IdentityCommonError(`The maximum size of a response must be a number of 0 or more, but is ${maxBytes}`)
  }
  const tooLarge = () => new IdentityCommonError(`The response is larger than the maximum of ${maxBytes} bytes`)

  // The header is optional, so the body is counted too
  const contentLength = response.headers.get('Content-Length')
  if (contentLength !== null && Number(contentLength) > maxBytes) {
    response.body?.cancel().catch(() => {})
    throw tooLarge()
  }

  if (!response.body) {
    const body = new Uint8Array(await response.arrayBuffer())
    if (body.length > maxBytes) throw tooLarge()
    return body
  }

  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let length = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    length += value.length
    if (length > maxBytes) {
      reader.cancel().catch(() => {})
      throw tooLarge()
    }
    chunks.push(value)
  }

  // Not `concatBytes(...chunks)`: a body of many small chunks would exceed the maximum number of arguments
  const body = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.length
  }
  return body
}
