import z from 'zod'

const hexToBytes = z.codec(z.hex(), z.instanceof(Uint8Array), {
  decode: (hexString) => z.util.hexToUint8Array(hexString),
  encode: (bytes) => z.util.uint8ArrayToHex(bytes),
})

export const hex = {
  decode: (data: string) => hexToBytes.decode(data),
  encode: (data: Uint8Array) => hexToBytes.encode(data as Uint8Array<ArrayBuffer>),
}
