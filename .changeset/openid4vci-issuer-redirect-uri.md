---
'@openid4vc/openid4vci': minor
---

Experimental support for the `issuer_redirect_uri` of a credential offer, which the wallet opens once the issuance flow has concluded.

**Experimental:** this implements [openid/OpenID4VCI#759](https://github.com/openid/OpenID4VCI/pull/759), which is not merged. It can change at any point to align with the specification.

- Issuers list the allowed values as `expected_redirect_uris` in the credential issuer metadata and pass one of them as `issuerRedirectUri` to `createCredentialOffer` or `Openid4vciIssuer.createCredentialOffer`. A value that is not listed throws.
- Wallets read it with the new `getIssuerRedirectUriFromCredentialOffer({ credentialOffer, issuerMetadata })`. It returns the `issuer_redirect_uri` when it is identical to one of the `expected_redirect_uris`, as the credential offer is not authenticated. Don't use `credentialOffer.issuer_redirect_uri` directly.
- An `issuer_redirect_uri` that is not one of the `expected_redirect_uris` is rejected: `getIssuerRedirectUriFromCredentialOffer` throws, and so do the `Openid4vciClient` methods that take a credential offer. When the credential issuer metadata has no `expected_redirect_uris`, the `issuer_redirect_uri` is ignored.

A credential offer with an `issuer_redirect_uri` that is not an https URL, and credential issuer metadata with `expected_redirect_uris` that is empty or contains a URL that is not https, are rejected.
