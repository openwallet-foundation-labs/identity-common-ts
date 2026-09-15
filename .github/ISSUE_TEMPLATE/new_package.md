---
name: New Package Proposal
about: Propose a new package to be added to the monorepo
title: '[Package Proposal]: '
labels: new-package
assignees: ''
---

## Package Name

Proposed name: `@owf/_______________`

## Category

- [ ] Core Identity Utility (generic, reusable across identity solutions)
- [ ] EUDI-Specific Tool (specific to EUDI Wallet ecosystem)

## Description

A clear and concise description of what this package would provide.

## Motivation

Why is this package needed? What problem does it solve?

## Scope

### What's In Scope

-
-

### What's Out of Scope

-
-

## API Design

Describe the proposed public API:

```typescript
// Example API surface
export interface SomeInterface {
  // ...
}

export function someFunction(): void
```

## Dependencies

What dependencies (if any) would this package require?

- [ ] Zero dependencies (preferred)
- [ ] Dependencies (list below)

## Platform Compatibility

How will this package ensure platform compatibility (Node.js, browsers, React Native)?

## Related Standards/Specifications

List any standards or specifications this package would implement:

-
-

## Existing Implementations

Are there existing implementations that could be migrated or used as reference?

- [ ] [EUDIPLO](https://github.com/openwallet-foundation-labs/eudiplo)
- [ ] [Paradym Wallet](https://github.com/animo/paradym-wallet)
- [ ] [EUDI Wallet Functionality](https://github.com/animo/eudi-wallet-functionality)
- [ ] Other: _____________

## Integration with Other OWF Projects

How would this package integrate with other OWF projects?

- [ ] oid4vc-ts
- [ ] openid-federation-ts
- [ ] credo-ts
- [ ] Other: _____________

## Implementation Plan

If you're willing to implement this, describe your plan:

1.
2.
3.

## Additional Context

Add any other context about the package proposal here.
