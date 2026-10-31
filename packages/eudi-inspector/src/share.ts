import { base64url } from '@owf/identity-common'

// A shared link carries the input in the fragment, after the #, which browsers do not send
// to the server. Long values are compressed, so a document fits in a link.

/** Links longer than this do not survive being pasted into most places */
export const MAX_LINK_LENGTH = 64_000

async function transform(bytes: Uint8Array, stream: CompressionStream | DecompressionStream): Promise<Uint8Array> {
  const output = new Blob([Uint8Array.from(bytes)]).stream().pipeThrough(stream)
  return new Uint8Array(await new Response(output).arrayBuffer())
}

/** Compress text, as base64url of its raw DEFLATE */
export async function compress(text: string): Promise<string> {
  return base64url.encode(await transform(new TextEncoder().encode(text), new CompressionStream('deflate-raw')))
}

/**
 * Decompress what {@link compress} produced. A value that is not compressed is returned
 * as it is, so a link can also be written by hand, e.g. `#doc=eyJ…`.
 */
export async function decompress(value: string): Promise<string> {
  try {
    const bytes = await transform(base64url.decode(value), new DecompressionStream('deflate-raw'))
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return value
  }
}

/** A value of the input of a page, and whether it is long enough to compress */
export interface SharedValue {
  name: string
  value: string
  compress: boolean
}

/** The fragment that holds the values, without the leading # */
export async function toFragment(values: SharedValue[]): Promise<string> {
  const params = new URLSearchParams()
  for (const { name, value, compress: shouldCompress } of values) {
    if (value) params.set(name, shouldCompress ? await compress(value) : value)
  }
  return params.toString()
}

/** Read the values of a fragment, decompressing those of the given names */
export async function fromFragment(hash: string, compressed: ReadonlySet<string>): Promise<Map<string, string>> {
  const values = new Map<string, string>()
  for (const [name, value] of new URLSearchParams(hash.replace(/^#/, ''))) {
    values.set(name, compressed.has(name) ? await decompress(value) : value)
  }
  return values
}
