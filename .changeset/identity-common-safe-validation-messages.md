---
'@owf/identity-common': patch
---

`validationErrorMessage`, and so the message of a `ValidationError`, escapes the control characters in the path and message of an issue, e.g. a line break as `\n`, and lists at most five errors at each level. A key of a record in the input can therefore no longer start a line of its own in a log, and the message no longer grows with the number of errors. A path segment longer than 200 characters, and an issue message longer than 1000, is cut off.

The new `errorMessageValue` escapes and cuts off a value in the same way, for an error message that includes a value of the input.
