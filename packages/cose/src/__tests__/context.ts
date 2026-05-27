import type { Mac0Context, Sign1Context } from '../cose'

export const sign1Context: Sign1Context = {
  sign: async () => new Uint8Array([1, 2, 3]),
  verify: async () => true,
  x509: {
    getIssuerNameField: () => ['a', 'v'],
    getPublicKey: async () => new Uint8Array([7, 8, 9]),
  },
}

export const mac0Context: Mac0Context = {
  authenticate: async () => new Uint8Array([4, 5, 6]),
  verify: async () => true,
}
