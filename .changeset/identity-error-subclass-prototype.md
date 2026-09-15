---
'@owf/identity-common': patch
---

Fix `instanceof` for subclasses of `IdentityError`. It set the prototype of every instance to `IdentityError.prototype`, so `new MyError() instanceof MyError` was false unless `MyError` set its prototype again, and always false for a subclass of `MyError`.
