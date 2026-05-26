import type { CoseKey, Mac0Context, Sign1, Sign1Context, SignatureAlgorithm } from '../cose'

export const sign1Context: Sign1Context = {
  sign: async (_options: {
    toBeSigned: Uint8Array
    key: CoseKey
    algorithm: SignatureAlgorithm
  }): Promise<Uint8Array> => new Uint8Array([1, 2, 3]),
  verify: async (_options: { sign1: Sign1; key: Uint8Array | CoseKey }): Promise<boolean> => true,
  x509: {
    getIssuerNameField: (_options: { certificate: Uint8Array; field: string }): string[] => ['a', 'v'],
    getPublicKey: async (_options: { certificate: Uint8Array; alg: string }): Promise<Uint8Array> =>
      new Uint8Array([7, 8, 9]),
  },
}

export const mac0Context: Mac0Context = {
  mac: async (_options: { toBeAuthenticated: Uint8Array; key: CoseKey | Uint8Array }): Promise<Uint8Array> =>
    new Uint8Array([4, 5, 6]),
}
