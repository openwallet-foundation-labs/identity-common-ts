import {
  AttributeTypeAndValue,
  AttributeValue,
  type Name,
  RelativeDistinguishedName,
  Name as X509Name,
} from '@peculiar/asn1-x509'
import { ATTRIBUTE_TYPES, type AttributeName } from './constants'
import { toHex } from './der'
import type { DistinguishedName, DistinguishedNameAttribute } from './types'
import { X509Exception } from './x509-exception'

const NAME_BY_OID = new Map<string, AttributeName>(
  Object.entries(ATTRIBUTE_TYPES).map(([name, oid]) => [oid, name as AttributeName])
)

/** Short names for the RFC 4514 representation (RFC 4514 clause 3 plus common extensions) */
const RFC4514_SHORT_NAMES: Partial<Record<AttributeName, string>> = {
  commonName: 'CN',
  surname: 'SN',
  serialNumber: 'SERIALNUMBER',
  countryName: 'C',
  localityName: 'L',
  stateOrProvinceName: 'ST',
  streetAddress: 'STREET',
  organizationName: 'O',
  organizationalUnitName: 'OU',
  title: 'T',
  givenName: 'GN',
  organizationIdentifier: 'organizationIdentifier',
  emailAddress: 'E',
}

function attributeValueToString(value: AttributeValue): string {
  if (value.anyValue) return `#${toHex(value.anyValue)}`
  return value.toString()
}

function escapeRfc4514(value: string): string {
  return value
    .replace(/[\\"+,;<>=]/g, (c) => `\\${c}`)
    .replace(/^[ #]/, (c) => `\\${c}`)
    .replace(/ $/, '\\ ')
}

/** Convert an ASN.1 Name into a {@link DistinguishedName}. */
export function parseName(name: Name): DistinguishedName {
  const attributes: DistinguishedNameAttribute[] = []
  const rdnStrings: string[] = []
  for (const rdn of name) {
    const parts: string[] = []
    for (const atv of rdn) {
      const attrName = NAME_BY_OID.get(atv.type)
      const value = attributeValueToString(atv.value)
      attributes.push({ type: atv.type, name: attrName, value })
      const key = (attrName && RFC4514_SHORT_NAMES[attrName]) ?? atv.type
      parts.push(`${key}=${atv.value.anyValue ? value : escapeRfc4514(value)}`)
    }
    rdnStrings.push(parts.join('+'))
  }

  const first = (n: AttributeName) => attributes.find((a) => a.name === n)?.value
  return {
    attributes,
    rfc4514: rdnStrings.reverse().join(','),
    commonName: first('commonName'),
    organizationName: first('organizationName'),
    organizationIdentifier: first('organizationIdentifier'),
    organizationalUnitNames: attributes.filter((a) => a.name === 'organizationalUnitName').map((a) => a.value),
    countryName: first('countryName'),
    localityName: first('localityName'),
    stateOrProvinceName: first('stateOrProvinceName'),
    serialNumber: first('serialNumber'),
    givenName: first('givenName'),
    surname: first('surname'),
    pseudonym: first('pseudonym'),
  }
}

/** Attributes that X.520 restricts to PrintableString */
const PRINTABLE_ATTRIBUTES = new Set<AttributeName>(['countryName', 'serialNumber'])

/** One name attribute: a well-known attribute name or an attribute type OID, and its value */
export type NameAttributeInput = readonly [AttributeName | string, string | undefined]

/**
 * Build an ASN.1 Name from attributes in encoding order (most general first), one attribute
 * per RDN. Empty values are skipped. `countryName` and `serialNumber` are encoded as
 * PrintableString, `emailAddress` as IA5String and everything else as UTF8String.
 */
export function buildName(attributes: readonly NameAttributeInput[]): Name {
  const rdns: RelativeDistinguishedName[] = []
  for (const [nameOrOid, value] of attributes) {
    if (value === undefined || value === '') continue
    const name = nameOrOid in ATTRIBUTE_TYPES ? (nameOrOid as AttributeName) : NAME_BY_OID.get(nameOrOid)
    if (!name && !/^\d+(\.\d+)+$/.test(nameOrOid)) {
      throw new X509Exception(`Unknown name attribute: ${nameOrOid}`)
    }
    const type = name ? ATTRIBUTE_TYPES[name] : nameOrOid
    const attributeValue =
      name && PRINTABLE_ATTRIBUTES.has(name)
        ? new AttributeValue({ printableString: value })
        : name === 'emailAddress'
          ? new AttributeValue({ ia5String: value })
          : new AttributeValue({ utf8String: value })
    rdns.push(new RelativeDistinguishedName([new AttributeTypeAndValue({ type, value: attributeValue })]))
  }
  return new X509Name(rdns)
}

function normalize(value: string): string {
  return value.trim().replace(/\s+/g, ' ').toLowerCase()
}

/**
 * Compare two distinguished names attribute by attribute, ignoring case and insignificant
 * whitespace in the values (a simplification of the RFC 5280 clause 7.1 matching rules).
 */
export function namesEqual(a: DistinguishedName, b: DistinguishedName): boolean {
  return (
    a.attributes.length === b.attributes.length &&
    a.attributes.every(
      (attr, i) => attr.type === b.attributes[i].type && normalize(attr.value) === normalize(b.attributes[i].value)
    )
  )
}
