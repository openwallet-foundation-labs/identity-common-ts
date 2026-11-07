# dcql

## 5.0.0

### Major Changes

- 163e447: `dcql` uses zod instead of valibot, like the other packages, and reports issues as the `ValidationIssue` of `@owf/identity-common`.
  
  Issues have a code of `DCQL_VALIDATION_CODES`, or a schema code of `@owf/identity-common` (`missing_value`, `invalid_type`, …) when the input does not have the structure of the schema. A credential that does not match the query gets, e.g., `claims_path_not_found`, `claim_values_mismatch` or `vct_mismatch`, and the mismatches carry the `expected` and the `actual` value as `context`. An empty array that must not be empty, such as `claims: []`, gives `empty_array`. `DcqlValidationIssue` types these issues, so checking the code narrows the context.
  
  `DcqlQuery.parse`, `DcqlPresentation.parse` and `DcqlPresentationResult.parse` throw a `DcqlParseError` with the `issues` of the input. Matching an array claim of a presentation against an empty array no longer throws a `TypeError`.
  
  **Breaking:**
  
  - The `issues` of failed claims, claim sets, meta and trusted authorities in a query or presentation result are a list of `ValidationIssue` (`severity`, `code`, `path`, `message`), with the `path` into the credential, instead of the flattened valibot issues. The failed entries no longer have an `output`.
  - The issues of a failed claim set are those of its own claims, not those of all failed claims of the credential query.
  - A missing claim whose claims query has `values` is reported as `Expected claim … to be defined`, not as a value mismatch with `undefined`.
  - The schemas are zod schemas, renamed from `vModel` to `zModel` and from `vFoo` to `zFoo`, e.g. `DcqlQuery.zModel` and `DcqlClaimsQuery.zMdocPath`. The `model` of the credential and presentation namespaces is removed: use `zModel.parse` or `zModel.safeParse`.
  - `DcqlQuery.parse` throws a `DcqlParseError` instead of a valibot `ValiError`.
  - `DcqlError` extends `IdentityError` of `@owf/identity-common`, like the errors of the other packages.
  - `DcqlQuery.parse` and `DcqlCredentialQuery.zModel` also run the checks of `DcqlQuery.validate`, with an issue at the exact location: `duplicate_credential_query_id` at `['credentials', i, 'id']`, `unknown_credential_query_id` at `['credential_sets', i, 'options', j, k]` and `unknown_claim_id` at `['credentials', i, 'claim_sets', j, k]`. `DcqlQuery.validate` and `DcqlCredentialQuery.validate` are deprecated and throw a `DcqlParseError` with these issues. `DcqlNonUniqueCredentialQueryIdsError`, `DcqlCredentialSetError` and `DcqlUndefinedClaimSetIdError` are removed.
  - `DcqlQuery.parse` rejects what OpenID4VP 1.0 does not allow and was accepted before: a claim `id` that is present more than once in `claims` (`duplicate_claim_id`, Section 6.3), a claim without `id` in a credential query with `claim_sets` (`missing_value`, Section 6.3), and an empty `vct_values` (`empty_array`, Appendix B.3.5).

### Patch Changes

- cb487f1: `DcqlQuery.parse` rejects a `meta` that is an array for `mso_mdoc`, `dc+sd-jwt` and `vc+sd-jwt` credential queries. It accepted one as an object without members, as valibot's object schema accepts arrays.
- Updated dependencies [ebd0b4b]
- Updated dependencies [ec2ed51]
- Updated dependencies [ec2ed51]
- Updated dependencies [cb487f1]
- Updated dependencies [5fff735]
- Updated dependencies [04cfd04]
  - @owf/identity-common@0.8.0

## 4.0.1

### Patch Changes

- 677d7ae: Merge claim outputs using own properties only. A credential with an object or array claim named after an `Object.prototype` member, such as `constructor` or `toString`, no longer fails the query.

## 4.0.0

### Major Changes

- 83b5118: Use `DcqlNotDisclosed` symbol sentinel to represent undisclosed array elements instead of `null`. This fixes an issue where claims containing explicit/literal `null` values were incorrectly rejected as missing during query parsing and dropped during object merging.

## 3.0.1

### Patch Changes

- 364f9c0: Move `dcql` from the `dcql-ts` repository into `identity-common-ts`. `dcql` keeps its own version line, separate from the other packages in this repository.
  
  The package stays ESM-only. Type declarations are exposed through the `types` export condition, and `main` points to the ESM build. `require('dcql')` loads the ESM build, which needs a Node.js version that supports `require(esm)` (Node.js 20.19 and later, or 22.12 and later).

## 3.0.0

### Major Changes

- 9fa8b0d: Remove support for the CommonJS/CJS syntax. Since React Native bundles your code, the update to ESM should not cause issues. In addition all latest minor releases of Node 20+ support requiring ESM modules. This means that even if you project is still a CommonJS project, it can now depend on ESM modules. For this reason DCQL is now fully an ESM module.

## 2.0.1

### Patch Changes

- 04c7029: Fix the CommonJS entry point and the types file reference in `package.json`.

## 2.0.0

### Major Changes

- 4ef6fc8: Add support for W3C VCDM 2.0 SD-JWT format.

### Minor Changes

- 8e29ab5: chore: update valibot to 1.1.0

### Patch Changes

- 0ab60c1: Fix querying a W3C `vc+sd-jwt` credential.

## 1.0.1

### Patch Changes

- 29c0b04: fix: rename Model class to ModelDefinition to prevent naming clash in ESM generated typescript types

## 1.0.0

### Major Changes

- 4d6aab5: bump version to 1.0 stable

## 0.5.1

### Patch Changes

- 9db1273: ci: add git tag for package publishing
- 3f12360: ci: typo and git tag creation

## 0.5.0

### Minor Changes

- d6db07d: feat: support multiple values for trusted authority of a credential. For example 'aki' trusted authority must match one of the hashes of the credential x509 chain, meaning multiple values could be provided for a single credential. Therefore values is now always an array, even though most (e.g. openid_federation) will only be bound to a single value.
- fe2beaa: refactor: always return `undefined` or a non-empty array for claims, credentials, trusted authorities, etc. This provides more consistency for the different places in the library where arrays are returned. If the value is defined, you can now always be sure there's at least one item in the array
- fe2beaa: refactor: passing an empty credential array to the dcql library will now return an normal result with `valid_credentials` and `failed_credentials` being `undefined` for all credentials from the DCQL query. This to still allow using the context of the DCQL query result to build the UI for a request.

## 0.4.2

### Patch Changes

- 0866100: refactor: update message for cryptographic holder binding for clarity

## 0.4.1

### Patch Changes

- 0916622: fix: do not include claim indexes not applicable for the current claim_set

## 0.4.0

### Minor Changes

- 2816b2d: feat: add support for the 'multiple' parameter in a DCQL query.

  When the 'multipe' keyword is present (which is 'false' by default) a presentation can have multiple credentials.
  It is still required for all presentations submitted to match against the query they are submitted to, even in the case
  of 'multiple' and there is already a valid match, as well as if a credential set is optional.

- b05782b: feat: add support for 'require_cryptographic_holder_binding' parameter.

  Each presentation passed to the `DcqlPresentationResult.fromDcqlPresentation` method, and each credential passed to the `DcqlQuery.query` method, must now include a `cryptographic_holder_binding` boolean property. Both will be checked against the DCQL query to ensure cryptographic holder binding is supported and present when required.

- 2816b2d: refactor: rename canBeSatisfied to can_be_satisfied for casing consistency
- 2816b2d: refactor of the whole structure returned by this library. It is a breaking change, but splits up all the checks into separate groups, including meta (vct, doctype, credential format, etc..), trusted authorities, and claims matching. It also includes detailed context on exactly which claims succeeded/failed, allowing for more control and insights into why a query did or didn't match

## 0.3.0

### Minor Changes

- 75638ba: feat: add support for 'trusted_authorities' in DCQL query.

  If 'trusted_authorities' is present in the query, the provided credential MUST have an 'authority' matching one of
  the trusted authorities from the query.

- ec16ec3: feat: add support for w3c credentials with the `ldp_vc` and `jwt_vc_json` formats.

  W3C credentials were already partly supported, but the OpenID4VP specification did not have a clear
  definition yet for DCQL with W3C VCs. We changed the format `jwt_vc_json-ld` to `ldp_vc` and added support
  for `meta.type_values` for W3C credential queries.

## 0.2.22

### Patch Changes

- bb9a3ce: fix: issue where canBeSatisfied would be true when the presentation was missing credentials and no credential_sets were used

## 0.2.21

### Patch Changes

- 67cd3b2: fix: handle the case where multiple claim sets would be present for a credential within a query

## 0.2.20

### Patch Changes

- 95526ca: add support for `intent_to_retain` for `mso_mdoc` claims query
- c3bb052: support new `path` syntax for `mso_mdoc` credential queries from OID4VP Draft 24, in addition the `namespace` and `claim_name` syntax from OID4VP Draft 22/23

## 0.2.19

### Patch Changes

- 4baba71: chore: change tooling
