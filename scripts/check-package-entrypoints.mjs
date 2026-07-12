#!/usr/bin/env node

import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'

const rootDir = process.cwd()
const packagesDir = join(rootDir, 'packages')

const expectedRootFields = {
  main: './dist/index.cjs',
  module: './dist/index.mjs',
  types: './dist/index.d.mts',
}

const expectedExports = {
  '.': {
    types: './dist/index.d.mts',
    import: './dist/index.mjs',
    require: './dist/index.cjs',
    default: './dist/index.mjs',
  },
  './package.json': './package.json',
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

function isEqual(left, right) {
  return stableStringify(left) === stableStringify(right)
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

    for (const [field, expectedValue] of Object.entries(expectedRootFields)) {
      if (packageJson[field] !== expectedValue) {
        packageFailures.push(formatMismatch(field, expectedValue, packageJson[field]))
      }
    }

    if (!isEqual(packageJson.exports, expectedExports)) {
      packageFailures.push(
        `  - exports: expected ${JSON.stringify(expectedExports)}, got ${JSON.stringify(packageJson.exports)}`
      )
    }

    if (!packageJson.publishConfig || packageJson.publishConfig.access !== 'public') {
      packageFailures.push('  - publishConfig.access: expected "public"')
    }

    for (const [field, expectedValue] of Object.entries(expectedRootFields)) {
      if (packageJson.publishConfig?.[field] !== expectedValue) {
        packageFailures.push(
          formatMismatch(`publishConfig.${field}`, expectedValue, packageJson.publishConfig?.[field])
        )
      }
    }

    if (!isEqual(packageJson.publishConfig?.exports, expectedExports)) {
      packageFailures.push(
        `  - publishConfig.exports: expected ${JSON.stringify(expectedExports)}, got ${JSON.stringify(packageJson.publishConfig?.exports)}`
      )
    }

    if (packageFailures.length > 0) {
      failures.push(`${entry.name}\n${packageFailures.join('\n')}`)
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
