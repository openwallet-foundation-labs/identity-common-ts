---
"dcql": patch
---

`DcqlQuery.query` and `DcqlPresentationResult.fromDcqlPresentation` build the parsers of a credential query once, instead of once for every credential they match against it. The results don't change.
