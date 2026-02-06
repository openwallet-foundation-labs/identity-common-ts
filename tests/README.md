# Integration Tests

This folder contains **integration tests** that span multiple packages in the monorepo.

## When to add tests here

- Tests that verify interactions between multiple `@owf/*` packages
- End-to-end scenarios that require multiple components working together
- Cross-package compatibility tests

## Unit tests

Unit tests for individual packages should be placed in each package's own test folder:

```text
packages/
  └── my-package/
      └── src/
          └── __tests__/
              └── my-package.test.mts
```

## Running tests

```bash
# Run all tests (unit + integration)
pnpm test

# Run only integration tests
pnpm test tests/integration
```
