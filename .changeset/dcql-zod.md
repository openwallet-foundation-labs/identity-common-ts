---
'dcql': major
---

`dcql` uses zod instead of valibot, like the other packages, and reports issues as the `ValidationIssue` of `@owf/identity-common`.

Issues have a code of `DCQL_VALIDATION_CODES`, or a schema code of `@owf/identity-common` (`missing_value`, `invalid_type`, …) when the input does not have the structure of the schema. A credential that does not match the query gets, e.g., `claim_missing`, `claim_value_mismatch` or `vct_mismatch`, and the mismatches carry the `expected` and the `actual` value as `context`. An empty array that must not be empty, such as `claims: []`, gives `empty_array`. `DcqlValidationIssue` types these issues, so checking the code narrows the context.

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
