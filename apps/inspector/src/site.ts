import type { DocumentKind } from './inspection'

/** A page of the inspector, served at `<id>/` */
export interface Page {
  id: DocumentKind
  /** Name in the navigation */
  name: string
  /** Heading of the page */
  title: string
  /** The specification and the forms of input */
  spec: string
  description: string
  /** Placeholder of the document field */
  placeholder?: string
}

/** The page that recognises any document */
export const HOME = {
  name: 'Any document',
  title: 'EUDI Inspector',
  description: 'Parse a document and check each element against its specification.',
  placeholder: 'Paste XML, JSON, a JWT or SD-JWT, CBOR as hex or base64url, or a PEM certificate, or drop a file here',
}

export const PAGES: Page[] = [
  {
    id: 'trusted-list',
    name: 'Trusted list',
    title: 'Trusted list inspector',
    spec: 'ETSI TS 119 612, XML',
    description:
      'Parse an ETSI TS 119 612 trusted list, check its structure and profile, and verify its signer against the EU List of Trusted Lists or a certificate you give.',
    placeholder: 'Paste the XML of a trusted list, or drop a file here',
  },
  {
    id: 'lote',
    name: 'LoTE',
    title: 'List of Trusted Entities inspector',
    spec: 'ETSI TS 119 602, JSON or JWS',
    description:
      'Parse an ETSI TS 119 602 List of Trusted Entities, check its structure and profile, and verify its signature.',
    placeholder: 'Paste a LoTE as JSON or JWS, or drop a file here',
  },
  {
    id: 'registration-certificate',
    name: 'Registration certificate',
    title: 'Registration certificate inspector',
    spec: 'ETSI TS 119 475, JWS',
    description:
      'Parse a registration certificate of a wallet-relying party, check it against ETSI TS 119 475, and check that it is for the subject of the access certificate.',
    placeholder: 'Paste a registration certificate (rc-wrp+jwt), or drop a file here',
  },
  {
    id: 'access-certificate',
    name: 'Access certificate',
    title: 'Access certificate inspector',
    spec: 'ETSI TS 119 411-8, PEM, base64 or DER',
    description:
      'Parse an X.509 certificate, check it against the access certificate profile of ETSI TS 119 411-8, and verify it with the certificate of its CA.',
    placeholder: 'Paste a certificate as PEM, base64 or hex, or drop a DER file here',
  },
  {
    id: 'status-list',
    name: 'Status list',
    title: 'Token Status List inspector',
    spec: 'draft-ietf-oauth-status-list, JWT',
    description:
      'Parse a Token Status List JWT, check its header and claims, count its statuses and look up the status at an index.',
    placeholder: 'Paste a status list JWT (statuslist+jwt), or drop a file here',
  },
  {
    id: 'sd-jwt',
    name: 'SD-JWT VC',
    title: 'SD-JWT inspector',
    spec: 'RFC 9901, with or without Key Binding',
    description:
      'Decode an SD-JWT or SD-JWT VC, resolve its disclosures, check its claims and Key Binding JWT, and verify its signatures.',
    placeholder: 'Paste an SD-JWT, with or without Key Binding JWT, or drop a file here',
  },
  {
    id: 'mdoc',
    name: 'mdoc',
    title: 'mdoc inspector',
    spec: 'ISO/IEC 18013-5, CBOR',
    description:
      'Decode an mdoc IssuerSigned or DeviceResponse, show its Mobile Security Object and elements, and match each element with its digest.',
    placeholder: 'Paste CBOR as hex or base64url, or drop a file here',
  },
  {
    id: 'over-asking',
    name: 'Over-asking',
    title: 'Over-asking check',
    spec: 'OpenID4VP request against ETSI TS 119 475',
    description:
      'Compare the DCQL query of an OpenID4VP request with the credentials and claims the relying party registered in its registration certificate.',
  },
]

export const pageOf = (id: string) => PAGES.find((page) => page.id === id)
