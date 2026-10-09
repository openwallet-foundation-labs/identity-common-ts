---
"@owf/cose": patch
---

import `cbor-x` through its pure JS `encode`/`decode` entry points, so bundling for Cloudflare Workers and other edge runtimes no longer pulls in the native `cbor-extract` loader and `child_process`. This also fixes `@owf/token-status-list` and `@owf/mdoc` in those runtimes.
