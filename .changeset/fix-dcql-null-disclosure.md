---
"dcql": major
---

Use `DcqlNotDisclosed` symbol sentinel to represent undisclosed array elements instead of `null`. This fixes an issue where claims containing explicit/literal `null` values were incorrectly rejected as missing during query parsing and dropped during object merging.
