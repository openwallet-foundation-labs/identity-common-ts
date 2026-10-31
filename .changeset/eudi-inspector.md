---
"@owf/eudi-inspector": minor
---

New package: parse EUDI trusted lists, LoTEs, registration and access certificates, Token Status Lists, SD-JWTs and mdocs, and check each element against its specification, with findings that point into the parsed document. Signatures are verified with a Web Crypto implementation the caller passes, including `x5c` chains against a given trust anchor and trusted lists against the EU LOTL. It also checks OpenID4VP requests for over-asking.

The command line tool `eudi-inspect` reads documents from files, URLs or standard input, prints the findings as text or JSON, and exits with 1 on errors. It can be built as a single executable with Node.js 25.7 or later.
