---
'@owf/eudi-access-certificate': patch
---

`validateAccessCertificate` accepts `acceptedPolicyOids: 'any'`, which accepts any certificate policy OID as the TSP allocated OID that ETSI TS 119 411-8 GEN-6.6.1-03 allows. Use it when the holder of a certificate checks its profile without knowing which OIDs its TSP allocates. A certificate without any policy OID is still rejected, and without the option only the TS 119 411-8 OIDs and the listed OIDs are accepted.
