---
'@owf/mdoc': minor
---

`DeviceResponse.createWithDeviceRequest` now takes a `documents` array instead of a single
`issuerSigned` list with one shared device key, so a response can disclose several documents that
each bring their own device key and device namespaces. Every document names the doc request it
answers through `docRequestIndex`, so a request may also be answered partially.
`Holder.createDeviceResponseForDeviceRequest` takes the same options.

```ts
await DeviceResponse.createWithDeviceRequest(
  {
    deviceRequest,
    sessionTranscript,
    documents: [{ issuerSigned, docRequestIndex: 0, signature: { signingKey } }],
  },
  ctx
)
```
