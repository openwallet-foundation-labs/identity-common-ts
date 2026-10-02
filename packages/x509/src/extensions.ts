import { AsnConvert } from '@peculiar/asn1-schema'
import type { Extension, GeneralName } from '@peculiar/asn1-x509'
import { ATTRIBUTE_TYPES } from './constants'
import { asn1ToString, parseDer } from './der'
import { toArrayBuffer } from './encoding'
import { parseName } from './name'
import type { SubjectAlternativeNames, X509Extension } from './types'
import { X509Exception } from './x509-exception'

/** Convert ASN.1 extensions, rejecting duplicates (RFC 5280 clause 4.2). */
export function toExtensions(extensions: Extension[] | undefined): X509Extension[] {
  const result = (extensions ?? []).map((e) => ({
    oid: e.extnID,
    critical: e.critical,
    value: new Uint8Array(e.extnValue.buffer),
  }))
  const seen = new Set<string>()
  for (const { oid } of result) {
    if (seen.has(oid)) throw new X509Exception(`Duplicate extension ${oid}`)
    seen.add(oid)
  }
  return result
}

/** Decode an extension value with an asn1-schema type, if the extension is present. */
export function decodeExtension<T>(
  extensions: X509Extension[],
  oid: string,
  type: new () => T,
  name: string
): T | undefined {
  const extension = extensions.find((e) => e.oid === oid)
  if (!extension) return undefined
  try {
    return AsnConvert.parse(toArrayBuffer(extension.value), type)
  } catch (error) {
    throw new X509Exception(`Invalid ${name} extension`, error)
  }
}

export function uriOf(name: GeneralName | undefined): string | undefined {
  return name?.uniformResourceIdentifier
}

export function urisOf(names: GeneralName[] | undefined): string[] {
  return (names ?? []).map(uriOf).filter((u): u is string => u !== undefined)
}

export function emptySubjectAlternativeNames(): SubjectAlternativeNames {
  return { dnsNames: [], uris: [], emails: [], ipAddresses: [], directoryNames: [], otherNames: [] }
}

export function toSubjectAlternativeNames(names: GeneralName[]): SubjectAlternativeNames {
  const result = emptySubjectAlternativeNames()
  for (const name of names) {
    if (name.uniformResourceIdentifier !== undefined) result.uris.push(name.uniformResourceIdentifier)
    else if (name.rfc822Name !== undefined) result.emails.push(name.rfc822Name)
    else if (name.dNSName !== undefined) result.dnsNames.push(name.dNSName)
    else if (name.iPAddress !== undefined) result.ipAddresses.push(name.iPAddress)
    else if (name.directoryName) result.directoryNames.push(parseName(name.directoryName))
    else if (name.otherName) {
      const value = new Uint8Array(name.otherName.value)
      let text: string | undefined
      try {
        text = asn1ToString(parseDer(value))
      } catch {
        // Not a string value
      }
      result.otherNames.push({ typeId: name.otherName.typeId, value, text })
    }
  }
  return result
}

/** Telephone numbers from otherName entries with type-id id-at-telephoneNumber */
export function telephoneNumbers(names: SubjectAlternativeNames): string[] {
  return names.otherNames
    .filter((o) => o.typeId === ATTRIBUTE_TYPES.telephoneNumber && o.text !== undefined)
    .map((o) => o.text as string)
}
