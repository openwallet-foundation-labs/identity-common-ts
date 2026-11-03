import { CborStructure } from '@owf/cose'
import { z } from 'zod'

// Oidc = [uint, tstr, tstr] - Array structure
const zOidcEncoded = z.tuple([z.number(), z.string(), z.string()])

// Easier structure for internal usage in class
const zOidcDecoded = z.object({
  version: z.number(),
  issuerUrl: z.string(),
  serverRetrievalToken: z.string(),
})

export type OidcEncodedStructure = z.infer<typeof zOidcEncoded>
export type OidcDecodedStructure = z.infer<typeof zOidcDecoded>
export type OidcOptions = OidcDecodedStructure

export class Oidc extends CborStructure<OidcEncodedStructure, OidcDecodedStructure> {
  public static override get encodingSchema() {
    return z.codec(zOidcEncoded, zOidcDecoded, {
      decode: ([version, issuerUrl, serverRetrievalToken]) => ({
        version,
        issuerUrl,
        serverRetrievalToken,
      }),
      encode: ({ version, issuerUrl, serverRetrievalToken }) =>
        [version, issuerUrl, serverRetrievalToken] satisfies OidcEncodedStructure,
    })
  }

  public get version() {
    return this.structure.version
  }

  public get issuerUrl() {
    return this.structure.issuerUrl
  }

  public get serverRetrievalToken() {
    return this.structure.serverRetrievalToken
  }

  public static create(options: OidcOptions): Oidc {
    return new Oidc({
      version: options.version,
      issuerUrl: options.issuerUrl,
      serverRetrievalToken: options.serverRetrievalToken,
    })
  }
}
