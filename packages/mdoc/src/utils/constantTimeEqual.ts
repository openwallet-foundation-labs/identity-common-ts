/**
 * Compares two byte arrays in a time that does not depend on where they differ, so checking a MAC
 * tag does not reveal how many of its bytes are right.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false

  let difference = 0
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i]

  return difference === 0
}
