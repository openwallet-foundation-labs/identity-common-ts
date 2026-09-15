---
'@owf/mdoc': minor
---

Fix the issuer checks against the document signer certificate (ISO/IEC 18013-5 7.2.1, 9.3.1):

- `issuing_country` and `issuing_jurisdiction` are compared with the `countryName` and `stateOrProvinceName` in the subject of the document signer certificate, instead of in its issuer. **Breaking:** the `x509.getIssuerNameField` context callback is replaced by `x509.getSubjectNameField`, which returns the fields of the subject distinguished name.
- `issuing_jurisdiction` is only checked when the document signer certificate has a `stateOrProvinceName`, as the check "is only required if the stateOrProvinceName element is present in the DS certificate". Before, it FAILED for every certificate without one.
- With `disableCertificateChainValidation`, verification no longer reports a FAILED `Unable to determine a trusted issuance chain` check, so `defaultVerificationCallback` no longer throws. The certificate chain of a status list or identifier list is then not validated either: the list is verified with the key of the leaf of its x5chain, and the revocation status is still checked. Before, verifying a credential with a status always FAILED without chain validation, as there were no trusted status certificates. `IssuerAuth.verifyStatus`, `verifyStatusListToken` and `verifyIdentifierListToken` accept `disableCertificateChainValidation` for the same, and then return no `chain`.
