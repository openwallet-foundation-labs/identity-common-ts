#!/usr/bin/env node

import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'

const rootDir = process.cwd()
const packagesDir = join(rootDir, 'packages')

// Within the workspace, packages export their TypeScript source, so tests and type checks don't need a build.
// The published entrypoints are configured in `publishConfig`, which pnpm applies when packing or publishing.
const sourceExports = './src/index.ts'

// Packages are either ESM-only, or ship both an ESM and a CommonJS build. ESM-only packages point `require`
// to the ESM build through the `default` condition, which Node.js supports through `require(esm)` (Node.js 20.19 and later, or 22.12 and later).
// Packages are being migrated to ESM-only.
const conventions = {
  'esm-only': {
    main: './dist/index.mjs',
    module: './dist/index.mjs',
    types: './dist/index.d.mts',
    exports: {
      '.': {
        types: './dist/index.d.mts',
        default: './dist/index.mjs',
      },
      './package.json': './package.json',
    },
  },
  'esm-and-cjs': {
    main: './dist/index.cjs',
    module: './dist/index.mjs',
    types: './dist/index.d.mts',
    exports: {
      '.': {
        types: './dist/index.d.mts',
        import: './dist/index.mjs',
        require: './dist/index.cjs',
        default: './dist/index.mjs',
      },
      './package.json': './package.json',
    },
  },
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entryValue]) => `${JSON.stringify(key)}:${stableStringify(entryValue)}`)
    return `{${entries.join(',')}}`
  }

  return JSON.stringify(value)
}

function formatMismatch(name, expected, actual) {
  return `  - ${name}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`
}

async function main() {
  const packageDirs = await readdir(packagesDir, { withFileTypes: true })
  const failures = []

  for (const entry of packageDirs) {
    if (!entry.isDirectory()) {
      continue
    }

    const packageJsonPath = join(packagesDir, entry.name, 'package.json')
    let packageJsonRaw

    try {
      packageJsonRaw = await readFile(packageJsonPath, 'utf8')
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
        continue
      }

      throw error
    }

    const packageJson = JSON.parse(packageJsonRaw)
    const packageFailures = []

    if (packageJson.exports !== sourceExports) {
      packageFailures.push(formatMismatch('exports', sourceExports, packageJson.exports))
    }

    for (const field of ['main', 'module', 'types']) {
      if (packageJson[field] !== undefined) {
        packageFailures.push(`  - ${field}: expected to only be set in publishConfig`)
      }
    }

    if (packageJson.publishConfig?.access !== 'public') {
      packageFailures.push('  - publishConfig.access: expected "public"')
    }

    // A package with a CommonJS entrypoint is checked against the ESM and CommonJS convention
    const conventionName = packageJson.publishConfig?.main === './dist/index.cjs' ? 'esm-and-cjs' : 'esm-only'
    for (const [field, expectedValue] of Object.entries(conventions[conventionName])) {
      const actualValue = packageJson.publishConfig?.[field]
      if (stableStringify(actualValue) !== stableStringify(expectedValue)) {
        packageFailures.push(formatMismatch(`publishConfig.${field}`, expectedValue, actualValue))
      }
    }

    if (packageFailures.length > 0) {
      failures.push(`${entry.name} (${conventionName})\n${packageFailures.join('\n')}`)
    }
  }

  if (failures.length > 0) {
    console.error('Package entrypoint validation failed:\n')
    console.error(failures.join('\n\n'))
    process.exit(1)
  }

  console.log('All package entrypoints match the workspace convention.')
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
