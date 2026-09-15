---
'@owf/identity-common': patch
---

Fix `instanceof` for subclasses of `IdentityException`.

`IdentityException` set the prototype of every instance to `IdentityException.prototype`, which overwrote the prototype `super()` had just installed. A subclass was therefore only recognizable by `instanceof` if it set its own prototype again, and a subclass of such a subclass was not recognizable at all:

```ts
class MyException extends IdentityException {}

new MyException('...') instanceof MyException // was false, is now true
```
