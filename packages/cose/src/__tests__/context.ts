import { CoseKey, type Mac0Context, type Sign1Context } from '../cose'

export const sign1Context: Sign1Context = {
  sign: async () => new Uint8Array([1, 2, 3]),
  verify: async () => true,
  x509: {
    getIssuerNameField: () => ['a', 'v'],
    getPublicKey: async () =>
      CoseKey.fromJwk({
        kty: 'EC',
        d: 'hGc90b8KMIjIpZos81yEFbOMc0Ww3k5ZNWICzDwtFV4',
        use: 'sig',
        crv: 'P-256',
        x: 'eBUFGSPkdYwJ9TqYpcNxhAyr-A8wlWzrLQJppSi3x0E',
        y: 'Jnf8v4steg6Gr4IEFpg_xcM5xdHKdngbQN9ERJbJvl8',
        alg: 'ES256',
      }),
  },
}

export const mac0Context: Mac0Context = {
  authenticate: async () => new Uint8Array([4, 5, 6]),
  verify: async () => true,
}
