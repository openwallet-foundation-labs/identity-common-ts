---
"@sd-jwt/sd-jwt-vc": patch
---

`svg_templates` in the type metadata rendering is now optional in the `TypeMetadataFormat` type. Parsing type metadata without `svg_templates` or `svg_template` no longer adds an `svg_templates: undefined` key.
