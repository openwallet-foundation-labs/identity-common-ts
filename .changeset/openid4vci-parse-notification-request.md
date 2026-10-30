---
"@openid4vc/openid4vci": patch
"@openid4vc/oauth2": patch
---

Add `Openid4vciIssuer.parseNotificationRequest` to validate a Notification Request at the issuer's notification endpoint. An invalid request throws an `Oauth2ServerErrorResponseError` with the new `Oauth2ErrorCodes.InvalidNotificationRequest`. `Oauth2ErrorCodes.InvalidNotificationId` is added for unknown notification ids.
