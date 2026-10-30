# EUDI Inspector

A browser tool that parses a document and checks each element against its specification, built on the packages of
this repository:

| Format | Specification | Input |
| --- | --- | --- |
| Trusted list | ETSI TS 119 612 | XML |
| List of Trusted Entities | ETSI TS 119 602 | JSON or JWS |
| Registration certificate | ETSI TS 119 475 | JWS |
| Access certificate | ETSI TS 119 411-8 | PEM, base64 or DER |
| Token Status List | draft-ietf-oauth-status-list-16 | JWT |
| SD-JWT and SD-JWT VC | RFC 9901, draft-ietf-oauth-sd-jwt-vc | compact, with or without Key Binding JWT |
| mdoc | ISO/IEC 18013-5 | IssuerSigned or DeviceResponse, CBOR as bytes, hex or base64url |

Documents can be pasted, dropped as a file or fetched from a URL. Everything runs in the browser. The findings come
from the validators of the packages, each with a path into the parsed document, so they are shown at the element they
concern. For a status list, it also counts the statuses and looks up the status at an index. For an SD-JWT, it
resolves the claims and shows the claim each disclosure discloses. For an mdoc, it shows the Mobile Security Object and
every element, and compares the digest of each element with the one in the MSO.

The checks of trusted lists, LoTEs, certificates and status lists come from the validators of the packages. Those of
SD-JWTs and mdocs are in the inspector (`src/sd-jwt.ts`, `src/mdoc.ts`), built on the decoding of `@sd-jwt/core` and
`@owf/mdoc`, as these packages verify with keys and report the first failure.

A second tool checks an OpenID4VP request for over-asking: it compares the DCQL query of the request with the
credentials and claims of the registration certificate of the relying party, using `checkOverAsking` of
`@owf/eudi-registration-certificate`. The request can be a request object, an authorization request as URL or JSON, a
Digital Credentials API request or only the DCQL query. The registration certificate is taken from `verifier_info` of
the request, or pasted. When the request object has an `x5c` header, the subject of the registration certificate is
compared with its access certificate. The tool opens directly at `#over-asking`.

## Development

```bash
pnpm --filter identity-inspector dev
```

The packages are used from their sources, so changes to them show up without a build.

## Deployment

`.github/workflows/pages.yml` builds the inspector and publishes it with the SD-JWT site under `/inspector/` on every
push to `main` that touches it or the packages it bundles. The build uses a relative base, so it works under any path.

## Limitations

- Fetching a URL needs the server to allow cross-origin requests. The EU List of Trusted Lists does, but several
  national trusted lists do not. Download those and drop the file instead.
- Signatures are only verified for trusted lists: the EU List of Trusted Lists against the signing certificates shipped
  with `@owf/eudi-tl`, other lists for integrity only. The JAdES signatures of LoTEs and registration certificates, the
  signatures of status lists and request objects, and the chains of access certificates, are not verified.
- A registration certificate inspected on its own is not compared with an access certificate; the over-asking check
  does that when the request object has one.
- Status lists are only read in JWT format, not as CWT.
- SD-JWTs are read in compact serialization, not as JSON. The type metadata of a vct is not fetched.
- The device signature or MAC of an mdoc DeviceResponse is not verified, as it needs the session transcript.
- A request passed by reference (`request_uri`) is not fetched; paste its request object instead.
