#!/usr/bin/env node

import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const rootDir = process.cwd()
const packagesDir = join(rootDir, 'packages')
const packageFilters = new Set(process.argv.slice(2))

async function getWorkspacePackages() {
  const entries = await readdir(packagesDir, { withFileTypes: true })
  const packages = []

  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue
    }

    const packageJsonPath = join(packagesDir, entry.name, 'package.json')
    let packageJson

    try {
      packageJson = JSON.parse(await readFile(packageJsonPath, 'utf8'))
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
        continue
      }

      throw error
    }

    if (
      !packageJson.name ||
      (packageFilters.size > 0 && !packageFilters.has(packageJson.name) && !packageFilters.has(entry.name))
    ) {
      continue
    }

    const esmEntry = packageJson.exports?.['.']?.import ?? packageJson.module
    if (!esmEntry) {
      continue
    }

    packages.push({
      name: packageJson.name,
      esmEntry: join(packagesDir, entry.name, esmEntry.replace(/^\.\//, '')),
    })
  }

  return packages.sort((left, right) => left.name.localeCompare(right.name))
}

async function main() {
  const packages = await getWorkspacePackages()
  const failures = []

  for (const { name, esmEntry } of packages) {
    try {
      await import(pathToFileURL(esmEntry).href)
      console.log(`ESM import ok: ${name}`)
    } catch (error) {
      failures.push({ packageName: name, error })
    }
  }

  if (failures.length > 0) {
    console.error('\nESM import validation failed:')
    for (const { packageName, error } of failures) {
      console.error(`\n${packageName}`)
      console.error(error)
    }
    process.exit(1)
  }

  console.log(`\nESM import validation passed for ${packages.length} package(s).`)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
