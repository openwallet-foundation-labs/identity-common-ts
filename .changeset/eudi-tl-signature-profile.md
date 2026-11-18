---
'@owf/eudi-tl': patch
---

`verifyTrustedListSignature`, `verifyEuLotlSignature`, `loadTrustedList` and `loadEuLotl` check the signature of a trusted list against the profile of ETSI TS 119 612 V2.4.1 Annex B.1.0 before any transform runs. Before, a transform of the signature, such as XPath, ran on the list before the signature was checked, so a large list could take quadratic time; and a signature that referenced another element than the `TrustServiceStatusList` verified, so its content was not covered. Now the signature may only use the enveloped-signature transform and canonicalization, each once per reference, and must reference the list itself once (`URI=""`, or the `Id` of the root that no other element has) and otherwise only its XAdES `SignedProperties`. A document with a second `TrustServiceStatusList` is rejected. The EU List of Trusted Lists and the national lists it points to conform.
