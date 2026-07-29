---
"@owf/eudi-wrprc": minor
---

Align the WRPRC payload with ETSI TS 119 475 v1.2.1.

- Add the Table 10 optional attributes `public_body`, `exp` and `intermediary.sname`, the latter replacing `intermediary.name`. Add the `act` claim required by GEN-5.2.4-09, and `intended_use_id` from Table 9.
- Add `iat` to `WRPRCPayloadSchema`. Table 7 lists it as a payload field, and the builder set it already, but `build()` parsed it away, so every payload it returned lost its issuance time.
- Accept entitlements in the Annex A.2 OID form as well as the URI form (GEN-5.2.4-03). Values outside Annex A still raise a warning.
- Validate that `exp` falls at most 12 months after `iat` (GEN-5.2.4-08), and that `act.sub` matches the intermediary identifier under intermediation (GEN-5.2.4-09).

Breaking: payloads carrying `intermediary.name`, and payloads without `iat`, no longer validate.
