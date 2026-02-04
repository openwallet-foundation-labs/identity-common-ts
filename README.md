<h1 align="center" ><b>Identity Common - TypeScript</b></h1>

<p align="center">
  <a href="https://typescriptlang.org">
    <img src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg" />
  </a>
</p>

<p align="center">
  <a href="#identity-common---owfidentity-common">Identity Common</a> 
  &nbsp;|&nbsp;
  <a href="#supported-environments">Supported Environments</a>
  &nbsp;|&nbsp;
  <a href="#contributing">Contributing</a>
  &nbsp;|&nbsp;
  <a href="#license">License</a>
</p>

---

## Identity Common - [`@owf/identity-common`](./packages/identity-common)

[![@owf/identity-common version](https://img.shields.io/npm/v/@owf/identity-common)](https://npmjs.com/package/@owf/identity-common)

Common tools for integrating with identity wallet ecosystems.

```ts
import {} from "@owf/identity-common";
```

## Supported Environments

This library is platform agnostic and support Node.JS, React Native and browsers out of the box, as long as it provides an implementation of `URL` and `URLSearchParams`. However because of this it is required to provide some callbacks for simple things like hashing, generate random bytes, etc. If no global `fetch` is available in your environment, this also need to be provided in the callbacks.

## Contributing

Is there something you'd like to fix or add? Great, we love community
contributions! To get involved, please follow our [contribution guidelines](./CONTRIBUTING.md).

## License

This project is licensed under the Apache License Version 2.0 (Apache-2.0).
