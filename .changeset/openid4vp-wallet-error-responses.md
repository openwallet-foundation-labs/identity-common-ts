---
"@openid4vc/openid4vp": patch
---

Wallets can create and submit OpenID4VP Authorization Error Responses (OpenID4VP 1.0 Section 8.5). `createOpenid4vpAuthorizationResponse` and `submitOpenid4vpAuthorizationResponse` accept an error payload such as `{ error: 'access_denied' }`, and an error response can be created without `jarm` options for a JARM response mode, for when the wallet cannot encrypt it (Section 8.3.1).

`resolveOpenid4vpAuthorizationRequest` throws the new `Openid4vpAuthorizationRequestError` when the request is invalid and its payload is known. It extends `Oauth2ServerErrorResponseError` and carries the `authorizationRequestPayload`, so the wallet can send the `errorResponse` to the verifier. `isClientAuthenticated` tells whether the client was authenticated: the JAR is verified and the client identifier is validated. When it is `false`, for example because the request object signature is invalid, the error can still be sent, but a `redirect_uri` returned by the response endpoint should not be opened. Errors before the payload is known, such as a failure to fetch the request object, are thrown as before.

```ts
try {
  await resolveOpenid4vpAuthorizationRequest({ authorizationRequestPayload, responseMode, callbacks })
} catch (error) {
  if (!(error instanceof Openid4vpAuthorizationRequestError)) throw error

  const request = error.authorizationRequestPayload
  // IAE requests are answered through the OpenID4VCI Interactive Authorization Endpoint instead
  if (isOpenid4vpAuthorizationRequestIae(request)) throw error

  const { authorizationResponsePayload } = await createOpenid4vpAuthorizationResponse({
    authorizationRequestPayload: request,
    authorizationResponsePayload: { error: error.errorResponse.error },
    callbacks,
  })

  if (isOpenid4vpAuthorizationRequestDcApi(request)) {
    // Return the authorizationResponsePayload through the Digital Credentials API
  } else {
    const { response } = await submitOpenid4vpAuthorizationResponse({
      authorizationRequestPayload: request,
      authorizationResponsePayload,
      callbacks,
    })
    // Only follow a returned redirect_uri when error.isClientAuthenticated is true
  }
}
```
