---
'@openid4vc/oauth2': minor
---

`Oauth2AuthorizationServer.parseAccessTokenRequest` accepts the `client_credentials` grant (RFC 6749 Section 4.4) and returns it as `{ grantType: 'client_credentials' }`. Like the other grants, it is rejected when the `authorizationServerMetadata` passed in does not list it in `grant_types_supported`. The new `Oauth2AuthorizationServer.verifyClientCredentialsAccessTokenRequest` verifies its DPoP proof and client attestation. Authenticating the client otherwise, for example with its client secret, and checking that it may use the grant (`unauthorized_client`, Section 5.2) is up to the authorization server. The `scope` of an access token request is now typed, and rejected when it is empty or not a string (Section 3.3).
