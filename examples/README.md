# Examples

Runnable examples for the packages in this repository. Examples are grouped by topic rather than by package, so a single example can combine multiple packages (for example issuing an SD-JWT VC with a status list from `@owf/token-status-list`).

```text
examples/
└── sd-jwt/
    ├── core/        # @sd-jwt/core
    └── sd-jwt-vc/   # @sd-jwt/sd-jwt-vc
```

## Running examples

Run an example with `tsx` from the repository root:

```bash
pnpm tsx examples/sd-jwt/core/basic.ts
```

Examples import packages by their published name (e.g. `@sd-jwt/core`), which resolves to the package source, so no build is needed. Packages used by examples are listed as `workspace:*` dev dependencies in the root `package.json`. Examples are type-checked as part of `pnpm types:check`.
