---
"@owf/cose": minor
---

fix: correctly handle detached payload vs payload on sign1 and mac0. The detached payload is not available on the Sign1 and Mac0 classes anymore, and should be provided to the method classes directly. Detached payload cannot be provided anymore when embedded payload is already present
