import { CborStructure, DataItem } from '@owf/cose'
import z from 'zod'
import { IssuerSignedItem } from './issuer-signed-item'

export const issuerNamespacesEncodedSchema = z.map(z.string(), z.array(z.instanceof(DataItem)))
export const issuerNamespacesDecodedSchema = z.map(z.string(), z.array(z.instanceof(IssuerSignedItem)))

export type IssuerNamespacesEncodedStructure = z.infer<typeof issuerNamespacesEncodedSchema>
export type IssuerNamespacesDecodedStructure = z.infer<typeof issuerNamespacesDecodedSchema>

export type IssuerNamespacesOptions = {
  issuerNamespaces: IssuerNamespacesDecodedStructure
}

export class IssuerNamespaces extends CborStructure<
  IssuerNamespacesEncodedStructure,
  IssuerNamespacesDecodedStructure
> {
  public static override get encodingSchema() {
    return z.codec(issuerNamespacesEncodedSchema, issuerNamespacesDecodedSchema, {
      decode: (encoded) => {
        const issuerNamespaces = new Map<string, IssuerSignedItem[]>()
        encoded.forEach((value, key) => {
          issuerNamespaces.set(
            key,
            value.map((isi) => IssuerSignedItem.fromDataItem(isi))
          )
        })

        return issuerNamespaces
      },
      encode: (decoded) => {
        const issuerNamespaces = new Map()
        decoded.forEach((value, key) => {
          issuerNamespaces.set(
            key,
            // Forward the issuer's own bytes for items we received rather than built. A
            // verifier digests the IssuerSignedItemBytes it is given and compares that to
            // valueDigests, so re-encoding from the decoded structure breaks the digest for
            // any issuer whose encoder differs from ours.
            value.map((isi) => isi.asDataItem)
          )
        })
        return issuerNamespaces
      },
    })
  }

  public get issuerNamespaces() {
    return this.structure
  }

  public getIssuerNamespace(namespace: string) {
    return this.structure.get(namespace)
  }

  public setIssuerNamespace(namespace: string, issuerSignedItems: IssuerSignedItem[]) {
    return this.structure.set(namespace, issuerSignedItems)
  }

  public static create(options: IssuerNamespacesOptions) {
    // biome-ignore lint/complexity/noThisInStatic: this.fromDecodedStructure is intentional for subclass support
    return this.fromDecodedStructure(options.issuerNamespaces)
  }
}
