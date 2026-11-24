---
'dcql': minor
---

`DcqlPresentation.parse` takes an optional `dcqlQuery`, to check a `vp_token` against the query before its presentations are verified. With it, the `DcqlParseError` also reports a key that is not the id of a credential query (`unknown_credential_query_id`), more than one presentation for a credential query without `multiple` (`multiple_presentations_not_allowed`), a presentation that is not the JSON type of its format (`invalid_type`), all OpenID4VP 1.0 Section 8.1, and a required credential query without a presentation (`missing_value`) or required credential set without an option that has a presentation for each of its credential queries (`unsatisfied_credential_set`, Section 6.4.2).

`DcqlPresentationResult.fromDcqlPresentation` throws its `DcqlPresentationResultError` for a credential query id that is not in the query with the same message as `DcqlPresentation.parse`. The messages of the `unknown_credential_query_id` and `unknown_claim_id` issues of `DcqlQuery.parse` quote `'credentials'` and `'claims'`.
