---
'@owf/identity-common': minor
---

Add `readResponseBodyAtMost(response, maxBytes)`, which reads the body of a fetch `Response` but rejects one larger than `maxBytes` with an `IdentityCommonError`. It checks `Content-Length` before reading, and cancels a body stream once it is larger. Where fetch has no body stream, as in React Native, it reads the body whole and checks it afterwards.

`bytesToString` takes a `stripByteOrderMark` option to remove a leading byte order mark, as `Response.text()` does.
