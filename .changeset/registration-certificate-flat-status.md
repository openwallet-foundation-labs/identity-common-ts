---
'@owf/eudi-registration-certificate': patch
---

Registration certificates with `idx` and `uri` directly in `status`, as ETSI TS 119 475 GEN-6.2.6.1-04 places them, are accepted. `zStatus` reads them as `status.status_list`, the shape of the Annex C example and the Token Status List, so `verifyRegistrationCertificateStatus` and the parsed payload are unchanged. Before, such a certificate failed with `status.status_list: expected object`.
