---
"@openid4vc/utils": patch
---

Accept data urls of the form "data:image/svg+xml;...". Previously usage of data urls with media type svg+xml would lead to errors when validating metadata.
