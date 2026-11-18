---
'@openid4vc/openid4vci': patch
---

`Openid4vciClient.initiateAuthorization` and `Openid4vciClient.createAuthorizationRequestUrlFromOffer` now send the `state` option in the authorization challenge, pushed authorization and authorization requests. Before, `state` was only sent to the interactive authorization endpoint and dropped in the other flows, so the authorization response could not be checked against it.
