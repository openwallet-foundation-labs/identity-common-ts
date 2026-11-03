#!/usr/bin/env node

// Prints the changelog entries of the published packages that match the given patterns, as the body of a GitHub release.
// Patterns use the syntax of the `fixed` groups in .changeset/config.json, e.g. `'@owf/*' '!@owf/mdoc'`.
// The published packages come from the `published-packages` output of changesets/action, in PUBLISHED_PACKAGES.

import { existsSync } from 'node:fs'
import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'

const packagesDir = join(process.cwd(), 'packages')

const toRegExp = (pattern) => new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replaceAll('*', '.*')}$`)
const patterns = process.argv.slice(2)
const include = patterns.filter((pattern) => !pattern.startsWith('!')).map(toRegExp)
const exclude = patterns.filter((pattern) => pattern.startsWith('!')).map((pattern) => toRegExp(pattern.slice(1)))
const matches = (name) => include.some((regExp) => regExp.test(name)) && !exclude.some((regExp) => regExp.test(name))

const packageDirs = new Map()
for (const dir of await readdir(packagesDir)) {
  const packageJsonPath = join(packagesDir, dir, 'package.json')
  if (!existsSync(packageJsonPath)) continue
  packageDirs.set(JSON.parse(await readFile(packageJsonPath, 'utf8')).name, join(packagesDir, dir))
}

const published = JSON.parse(process.env.PUBLISHED_PACKAGES || '[]')
  .filter(({ name }) => matches(name))
  .sort((a, b) => a.name.localeCompare(b.name))

const sections = []
for (const { name, version } of published) {
  const changelog = await readFile(join(packageDirs.get(name), 'CHANGELOG.md'), 'utf8')
  // The entry of a version runs from its `## <version>` heading up to the heading of the previous version
  const entry = changelog.split(/^## /m).find((section) => section.split('\n')[0].trim() === version)
  if (!entry) throw new Error(`No changelog entry for ${name}@${version}`)
  sections.push(`## ${name}\n\n${entry.slice(version.length).trim()}`)
}

console.log(sections.join('\n\n'))
