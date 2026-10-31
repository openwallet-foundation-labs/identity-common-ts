# EUDI Inspector

A browser tool that parses a document and checks each element against its specification. The parsing and the checks
are those of [`@owf/eudi-inspector`](../../packages/eudi-inspector), which also has them as the command line tool
`eudi-inspect`; these pages add the input forms and the document tree. Each format has its own page, with the inputs its
further checks need:

| Page | Specification | Input | Further inputs |
| --- | --- | --- | --- |
| `trusted-list/` | ETSI TS 119 612 | XML | Check the signer against the EU LOTL, or against certificates |
| `lote/` | ETSI TS 119 602 | JSON or JWS | Signer key or trust anchor |
| `registration-certificate/` | ETSI TS 119 475 | JWS | Access certificate of the relying party, signer key or trust anchor |
| `access-certificate/` | ETSI TS 119 411-8 | PEM, base64 or DER | Certificate of the issuing CA |
| `status-list/` | draft-ietf-oauth-status-list-16 | JWT | uri of the reference, signer key or trust anchor |
| `sd-jwt/` | RFC 9901, draft-ietf-oauth-sd-jwt-vc | compact, with or without Key Binding JWT | Issuer key or trust anchor, expected nonce and aud |
| `mdoc/` | ISO/IEC 18013-5 | IssuerSigned or DeviceResponse, CBOR as bytes, hex or base64url | |
| `over-asking/` | OpenID4VP, ETSI TS 119 475 | Request and registration certificate | |

The start page takes any document, recognises its format, and loads only the parsers of that format. From its result,
a link opens the document in the page of its format for the further checks. A format page that is given a document of
another format points to the right page.

Documents can be pasted, dropped as a file or fetched from a URL. The findings come from the validators of the packages,
each with a path into the parsed document, so they are shown at the element they concern. For a status list, the page
also counts the statuses and looks up the status at an index. For an SD-JWT, it resolves the claims and shows the claim
each disclosure discloses. For an mdoc, it shows the Mobile Security Object and every element, and compares the digest
of each element with the one in the MSO.

The checks of trusted lists, LoTEs, certificates and status lists come from the validators of the packages. Those of
SD-JWTs and mdocs are in `@owf/eudi-inspector`, built on the decoding of `@sd-jwt/core` and `@owf/mdoc`, as these
packages verify with keys and report the first failure.

## Signatures

Signatures are verified with the Web Crypto API of the browser, which the pages pass to `@owf/eudi-inspector`:

- A JWS is verified with the key you give, as JWK, JWK Set or certificates, or else with the `x5c` of its header. When
  you give a certificate and the header has an `x5c`, the chain of the `x5c` has to lead to it, so it acts as the trust
  anchor. Without a trust anchor, a valid signature proves integrity only.
- The Key Binding JWT of an SD-JWT is verified with the key in `cnf`.
- The EU List of Trusted Lists is verified against the signing certificates shipped with `@owf/eudi-tl`. Another
  trusted list is verified against the certificates you give, or against those the EU LOTL lists for its territory,
  which the page then fetches from `ec.europa.eu`.
- An access certificate is verified with the certificate of its CA.

## Examples

Each page offers examples that show what it checks: documents that pass, and documents with a planted problem, each
with a description of what it shows. The start page offers a few of them. An example opens as `#example=<id>`, e.g.
`sd-jwt/#example=other-verifier`, so it can be linked to.

`scripts/examples.ts` makes them into `src/examples/`. The signed examples are made with throwaway keys and certificates
of the test CA of `@owf/eudi-access-certificate`, valid until 2036, and the keys are not kept. To make them again:

```bash
pnpm --filter identity-inspector examples
```

`src/__tests__/examples.test.mts` runs every example as its page does and checks the findings and signature results it
was made to show, so an example that expires or changes fails the tests.

## Sharing a result

"Copy link to this result" puts the input of the page into the fragment of the URL, after the `#`, which browsers do not
send to the server. Long values are compressed with raw DEFLATE and encoded as base64url. A fetched document is shared as
its URL, so the link fetches it again. Links can also be written by hand, with values as they are:

```text
trusted-list/#url=https://ec.europa.eu/tools/lotl/eu-lotl.xml
sd-jwt/#doc=eyJ…~&nonce=n-0S6&aud=https://verifier.example
status-list/#doc=eyJ…&uri=https://example.com/statuslists/1&lookup=42
```

The names are those of the fields of the page: `url` or `doc` for the document, `lookup` for the index of a status list,
and `key`, `nonce`, `aud`, `uri`, `access`, `issuer`, `signers`, `lotl`, `request` and `registration`. A link holds the
input in full, so anyone with the link sees it.

## Privacy

Everything runs in the browser: nothing that is pasted, dropped or checked is sent to a server. Once loaded, a page only
makes a request to fetch a URL you give, or the EU LOTL when you check a signer against it. A shared link holds its
input in the fragment, which does not reach the server either.

## Development

```bash
pnpm --filter identity-inspector dev
```

The packages are used from their sources, so changes to them show up without a build. Each page is an `index.html` in
the folder of its name; `layout.ts` adds the header, navigation, result area and footer they share when they are built,
and `src/site.ts` lists the pages. The start page loads the parsers of a format through its module in `src/formats/`,
so each format is a chunk of its own.

## Deployment

`.github/workflows/pages.yml` builds the inspector and publishes it with the SD-JWT site under `/inspector/` on every
push to `main` that touches it or the packages it bundles. The build uses a relative base, so it works under any path.

## Limitations

- Fetching a URL needs the server to allow cross-origin requests. The EU List of Trusted Lists does, but the national
  trusted lists do not. Download those and drop the file instead.
- The issuer signature of an mdoc, the device signature or MAC of a DeviceResponse, and the signatures of request
  objects are not verified. A JWS signed with a key named by `kid` alone needs that key to be given.
- Revocation is not checked: neither the CRLs of certificates nor the status of an SD-JWT VC or mdoc.
- Status lists are only read in JWT format, not as CWT.
- SD-JWTs are read in compact serialization, not as JSON. The type metadata of a vct is not fetched.
- A request passed by reference (`request_uri`) is not fetched; paste its request object instead.
