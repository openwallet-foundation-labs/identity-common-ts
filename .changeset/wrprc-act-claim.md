---
"@owf/eudi-registration-certificate": minor
---

Add the `act` claim (ETSI TS 119 475 v1.2.1, GEN-5.2.4-09): an `ActSchema` and an optional `act` field on the WRPRC payload, a `.act({ sub })` builder setter, and a validator check (`ACT_SUB_MISMATCH`) enforcing that `act.sub` equals `intermediary.sub` when `act` is present. `act` is not made mandatory under intermediation, so existing intermediated payloads remain valid.
