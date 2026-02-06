# Contributing to Identity Common TypeScript

Thank you for your interest in contributing to Identity Common TypeScript! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Adding a New Package](#adding-a-new-package)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

This project follows the [OpenWallet Foundation Code of Conduct](https://tac.openwallet.foundation/governance/code-of-conduct/). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) >= 20
- [pnpm](https://pnpm.io/) (version specified in `package.json` under `packageManager`)

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/openwallet-foundation-labs/identity-common-ts.git
   cd identity-common-ts
   ```

2. Install dependencies:

   ```bash
   pnpm install
   ```

3. Build all packages:

   ```bash
   pnpm build
   ```

4. Run tests:

   ```bash
   pnpm test
   ```

## Project Structure

This is a monorepo managed with [pnpm workspaces](https://pnpm.io/workspaces). The structure is organized as follows:

```text
identity-common-ts/
├── packages/                    # All publishable packages
│   ├── identity-common/         # Core identity utilities (base package)
│   ├── jose/                    # JOSE/JWT implementation (planned)
│   ├── cose/                    # COSE/CWT implementation (planned)
│   ├── x509/                    # X.509 certificate utilities (planned)
│   ├── token-status-list/       # JWT/CWT Token Status List (planned)
│   └── eudi-*/                  # EUDI-specific packages (planned)
├── tests/                       # Integration tests
├── .changeset/                  # Changeset configuration for versioning
└── .github/                     # GitHub Actions workflows
```

### Package Categories

Packages are organized into two main categories:

1. **Core Identity Utilities** (`@owf/identity-*`)
   - Generic, reusable utilities for any identity solution
   - Platform agnostic (Node.js, browsers, React Native)
   - Minimal dependencies

2. **EUDI-Specific Tools** (`@owf/eudi-*`)
   - Tools specific to the European Digital Identity Wallet ecosystem
   - Built on top of core utilities
   - Implements ETSI and ARF specifications

## Development Workflow

### Available Scripts

From the root of the repository:

| Command | Description |
| ------- | ----------- |
| `pnpm build` | Build all packages |
| `pnpm test` | Run all tests |
| `pnpm types:check` | Type-check all packages |
| `pnpm style:check` | Check code style with Biome |
| `pnpm style:fix` | Fix code style issues |
| `pnpm md:check` | Check markdown files |
| `pnpm md:fix` | Fix markdown issues |

### Working on a Package

1. Navigate to the package directory or work from the root
2. Make your changes
3. Run tests: `pnpm test`
4. Check types: `pnpm types:check`
5. Check/fix style: `pnpm style:fix`
6. Check/fix markdown: `pnpm md:fix`

## Adding a New Package

Follow these steps to add a new package to the monorepo:

### 1. Create the Package Directory

```bash
mkdir -p packages/my-package/src
```

### 2. Create `package.json`

Create `packages/my-package/package.json`:

```json
{
  "name": "@owf/my-package",
  "version": "0.0.0",
  "description": "Description of your package",
  "files": ["dist"],
  "license": "Apache-2.0",
  "exports": "./src/index.ts",
  "homepage": "https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/my-package",
  "repository": {
    "type": "git",
    "url": "https://github.com/openwallet-foundation-labs/identity-common-ts",
    "directory": "packages/my-package"
  },
  "publishConfig": {
    "module": "./dist/index.mjs",
    "types": "./dist/index.d.mts",
    "exports": {
      ".": "./dist/index.mjs",
      "./package.json": "./package.json"
    }
  },
  "scripts": {
    "build": "tsdown src/index.ts --format esm --dts --sourcemap"
  },
  "dependencies": {},
  "devDependencies": {}
}
```

**Naming conventions:**

- Core utilities: `@owf/identity-<name>` or `@owf/<name>` (e.g., `@owf/jose`, `@owf/x509`)
- EUDI-specific: `@owf/eudi-<name>` (e.g., `@owf/eudi-lote`, `@owf/eudi-payment`)

### 3. Create TypeScript Configuration

Create `packages/my-package/tsconfig.json`:

```json
{
  "extends": "../../tsconfig.json",
  "compilerOptions": {
    "outDir": "dist",
    "rootDir": "src"
  },
  "include": ["src"]
}
```

### 4. Create Source Files

Create `packages/my-package/src/index.ts`:

```typescript
// Export your public API here
export {}
```

### 5. Create README

Create `packages/my-package/README.md`:

```markdown
# @owf/my-package

Description of your package.

## Installation

```bash
npm install @owf/my-package
# or
pnpm add @owf/my-package
# or
yarn add @owf/my-package
```

## Usage

```typescript
import { } from '@owf/my-package'
```

## API Reference

Document your public API here.

## License

This project is licensed under the Apache License Version 2.0 (Apache-2.0).

### 6. Add Tests

Create tests in `packages/my-package/src/__tests__/`:

```typescript
// packages/my-package/src/__tests__/my-package.test.mts
import { describe, it, expect } from 'vitest'

describe('my-package', () => {
  it('should work', () => {
    expect(true).toBe(true)
  })
})
```

### 7. Update Root Configuration (if needed)

If your package needs to be available in the root `package.json` for testing:

```json
{
  "devDependencies": {
    "@owf/my-package": "workspace:*"
  }
}
```

### 8. Install and Build

```bash
pnpm install
pnpm build
```

## Coding Standards

### TypeScript

- Use strict TypeScript (`"strict": true`)
- Export types explicitly
- Avoid `any` - use `unknown` when type is truly unknown
- Document public APIs with JSDoc comments

### Platform Agnostic

This library must work across Node.js, browsers, and React Native:

- **No platform-specific APIs**: Don't use Node.js `crypto`, `fs`, `Buffer`, etc.
- **Callback-based crypto**: Accept crypto operations as callbacks
- **Standard APIs only**: Use `Uint8Array` instead of `Buffer`, `URL`/`URLSearchParams` for URLs
- **No native dependencies**: Avoid packages with native bindings

Example of platform-agnostic design:

```typescript
// ❌ Don't do this
import { createHash } from 'crypto'
const hash = createHash('sha256').update(data).digest()

// ✅ Do this instead
interface CryptoCallbacks {
  sha256(data: Uint8Array): Promise<Uint8Array>
}

function myFunction(data: Uint8Array, crypto: CryptoCallbacks) {
  const hash = await crypto.sha256(data)
  // ...
}
```

### Code Style

We use [Biome](https://biomejs.dev/) for linting and formatting:

- 2 spaces for indentation
- Single quotes for strings
- No semicolons (except where required)
- 120 character line width

Run `pnpm style:fix` before committing.

## Testing

We use [Vitest](https://vitest.dev/) for testing.

### Running Tests

```bash
# Run all tests
pnpm test

# Run tests in watch mode
pnpm test --watch

# Run tests for a specific package
pnpm test --filter @owf/my-package
```

### Writing Tests

- Place tests in `src/__tests__/` within each package
- Use `.test.mts` extension for test files
- Test public API behavior, not implementation details
- Include edge cases and error conditions

## Submitting Changes

### Creating a Pull Request

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run checks: `pnpm test && pnpm types:check && pnpm style:check`
5. Create a changeset (if your changes affect published packages)
6. Commit your changes
7. Push and create a Pull Request

### Changesets

We use [Changesets](https://github.com/changesets/changesets) for version management.

If your changes affect any published package, create a changeset:

```bash
pnpm changeset
```

Follow the prompts to:

1. Select the packages that changed
2. Choose the semver bump type (major/minor/patch)
3. Write a summary of changes

**When to create a changeset:**

- Adding new features (minor)
- Fixing bugs (patch)
- Breaking changes (major)
- Documentation improvements that affect the published package (patch)

**When NOT to create a changeset:**

- Changes to CI/CD
- Changes to root-level dev dependencies
- Changes to documentation outside packages

## Release Process

Releases are automated via GitHub Actions:

1. Changesets accumulate in PRs
2. A "Version Packages" PR is automatically created/updated
3. Merging the Version PR triggers a release to npm

Maintainers will handle the release process.

## Questions?

If you have questions, feel free to:

- Open a [GitHub Discussion](https://github.com/openwallet-foundation-labs/identity-common-ts/discussions)
- Join the [OpenWallet Foundation community](https://openwallet.foundation/community/)

Thank you for contributing! 🎉
