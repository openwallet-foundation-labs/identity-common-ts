# SD-JWT Examples

Examples for [`@sd-jwt/core`](../../packages/sd-jwt-core) and [`@sd-jwt/sd-jwt-vc`](../../packages/sd-jwt-vc). Run them from the repository root after `pnpm build`:

```bash
pnpm tsx examples/sd-jwt/core/basic.ts
pnpm tsx examples/sd-jwt/sd-jwt-vc/basic.ts
```

## SD-JWT (`@sd-jwt/core`)

| Example | Description |
|---------|-------------|
| [`basic.ts`](./core/basic.ts) | Issue, validate, present, and verify an SD-JWT |
| [`all.ts`](./core/all.ts) | Issue, present, and verify a comprehensive set of claims |
| [`custom.ts`](./core/custom.ts) | Custom hasher and salt generator |
| [`custom-header.ts`](./core/custom-header.ts) | Custom JWT header |
| [`custom-verify.ts`](./core/custom-verify.ts) | Verifier that receives extra verification options |
| [`sdjwt-object.ts`](./core/sdjwt-object.ts) | Working with the decoded SD-JWT object |
| [`decoy.ts`](./core/decoy.ts) | Adding decoy digests |
| [`kb.ts`](./core/kb.ts) | Key binding |
| [`decode.ts`](./core/decode.ts) | Decoding an SD-JWT with `SDJwtInstance` |
| [`decode-functions.ts`](./core/decode-functions.ts) | Decoding an SD-JWT with the standalone decode functions |
| [`present-functions.ts`](./core/present-functions.ts) | Presenting an SD-JWT with the standalone present functions |
| [`flatten-json.ts`](./core/flatten-json.ts) | Flattened JWS JSON serialization |
| [`general-json.ts`](./core/general-json.ts) | General JWS JSON serialization |

## SD-JWT VC (`@sd-jwt/sd-jwt-vc`)

| Example | Description |
|---------|-------------|
| [`basic.ts`](./sd-jwt-vc/basic.ts) | Issue, validate, present, and verify an SD-JWT VC |
| [`all.ts`](./sd-jwt-vc/all.ts) | Issue, present, and verify a comprehensive set of claims |
| [`custom.ts`](./sd-jwt-vc/custom.ts) | Custom hasher and salt generator |
| [`custom-header.ts`](./sd-jwt-vc/custom-header.ts) | Custom JWT header |
| [`sdjwt-object.ts`](./sd-jwt-vc/sdjwt-object.ts) | Working with the decoded SD-JWT object |
| [`decoy.ts`](./sd-jwt-vc/decoy.ts) | Adding decoy digests |
| [`kb.ts`](./sd-jwt-vc/kb.ts) | Key binding |
| [`decode.ts`](./sd-jwt-vc/decode.ts) | Decoding an SD-JWT VC |
