# Identity Common TS

- Packages should never depend on global crypto. It should be provided as a callback. We provide the crypto package, which is the exception, as it can be used as a crypto implementation based on the WebCrypto APIs.
