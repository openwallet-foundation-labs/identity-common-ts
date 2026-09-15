#!/usr/bin/env node

/**
 * Validates that the built packages can be imported and required as they are published.
 *
 * Within the workspace packages export their TypeScript source, so the packages are packed first
 * (which applies `publishConfig`) and installed into a temporary project. Run `pnpm build` before this script.
 *
 * Usage: node scripts/check-package-esm-imports.mjs [package-name...]
 */

import { execFileSync, spawnSync } from 'node:child_process'
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const rootDir = process.cwd()
const packageFilters = new Set(process.argv.slice(2))

async function main() {
  const tempDir = await mkdtemp(join(tmpdir(), 'identity-common-esm-check-'))

  try {
    execFileSync('pnpm', ['-r', '--silent', 'pack', '--pack-destination', tempDir], { cwd: rootDir, stdio: 'ignore' })

    const tarballs = (await readdir(tempDir)).filter((file) => file.endsWith('.tgz'))
    const dependencies = {}
    for (const tarball of tarballs) {
      const manifest = execFileSync('tar', ['-xOf', join(tempDir, tarball), 'package/package.json'], {
        encoding: 'utf8',
      })
      dependencies[JSON.parse(manifest).name] = `file:./${tarball}`
    }

    // Overrides make sure dependencies between workspace packages resolve to the packed tarballs, not the registry
    const overrides = Object.fromEntries(Object.keys(dependencies).map((name) => [name, `$${name}`]))
    await writeFile(
      join(tempDir, 'package.json'),
      JSON.stringify({ name: 'esm-check', private: true, dependencies, overrides }, null, 2)
    )
    execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--loglevel=error'], {
      cwd: tempDir,
      stdio: 'inherit',
    })

    const packageNames = Object.keys(dependencies)
      .filter((name) => packageFilters.size === 0 || packageFilters.has(name))
      .sort()
    const failures = []

    for (const name of packageNames) {
      // `require` loads ESM-only packages through `require(esm)`, which fails for instance on top-level await
      const checks = [
        ['import', ['--input-type=module', '-e', `await import(${JSON.stringify(name)})`]],
        ['require', ['--input-type=commonjs', '-e', `require(${JSON.stringify(name)})`]],
      ]

      for (const [kind, args] of checks) {
        const result = spawnSync(process.execPath, args, { cwd: tempDir, encoding: 'utf8' })
        if (result.status === 0) {
          console.log(`${kind} ok: ${name}`)
        } else {
          failures.push({ packageName: name, kind, error: result.stderr })
        }
      }
    }

    if (failures.length > 0) {
      console.error('\nESM import or require validation failed:')
      for (const { packageName, kind, error } of failures) {
        console.error(`\n${packageName} (${kind})`)
        console.error(error)
      }
      process.exit(1)
    }

    console.log(`\nESM import and require validation passed for ${packageNames.length} package(s).`)
  } finally {
    await rm(tempDir, { recursive: true, force: true })
  }
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
