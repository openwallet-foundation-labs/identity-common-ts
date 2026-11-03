#!/usr/bin/env node

/**
 * Versions one package for a release, without the other packages. See "Releasing a Single Package" in CONTRIBUTING.md.
 *
 * Usage: node scripts/release-package.mjs <package-name>
 *
 * Runs `changeset version` with only the changesets of the package and of the packages in its fixed group. All other
 * changesets stay pending. A changeset that also bumps other packages stays pending with only those packages.
 */

import { execFileSync } from 'node:child_process'
import { appendFile, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { join, matchesGlob } from 'node:path'

const rootDir = process.cwd()
const packagesDir = join(rootDir, 'packages')
const changesetDir = join(rootDir, '.changeset')

async function readPackages() {
  const packages = new Map()

  for (const entry of await readdir(packagesDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) {
      continue
    }

    try {
      const packageJson = JSON.parse(await readFile(join(packagesDir, entry.name, 'package.json'), 'utf8'))
      packages.set(packageJson.name, packageJson)
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
        continue
      }

      throw error
    }
  }

  return packages
}

async function readChangesets() {
  const changesets = []

  for (const file of await readdir(changesetDir)) {
    if (!file.endsWith('.md') || file === 'README.md') {
      continue
    }

    const path = join(changesetDir, file)
    const content = await readFile(path, 'utf8')
    const end = content.indexOf('\n---\n', 3)
    if (!content.startsWith('---\n') || end === -1) {
      throw new Error(`${file} has no frontmatter`)
    }

    const releases = content
      .slice(4, end)
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line) => {
        const separator = line.lastIndexOf(':')
        return {
          name: line
            .slice(0, separator)
            .trim()
            .replace(/^['"]|['"]$/g, ''),
          type: line.slice(separator + 1).trim(),
        }
      })

    changesets.push({ file, path, content, releases, summary: content.slice(end + 5) })
  }

  return changesets
}

function formatChangeset(releases, summary) {
  return `---\n${releases.map(({ name, type }) => `'${name}': ${type}`).join('\n')}\n---\n${summary}`
}

// Same as changesets: a package is in a fixed group when it matches a pattern of the group and none of its negated patterns.
function isInGroup(name, group) {
  return (
    group.some((pattern) => !pattern.startsWith('!') && matchesGlob(name, pattern)) &&
    !group.some((pattern) => pattern.startsWith('!') && matchesGlob(name, pattern.slice(1)))
  )
}

async function main() {
  const name = process.argv[2]
  if (!name) {
    console.error('Usage: node scripts/release-package.mjs <package-name>')
    process.exit(1)
  }

  const packages = await readPackages()
  if (!packages.has(name)) {
    throw new Error(`${name} is not a package of this repository`)
  }

  // Packages of a fixed group always have the same version, so they are released together
  const config = JSON.parse(await readFile(join(changesetDir, 'config.json'), 'utf8'))
  const group = config.fixed.find((group) => isInGroup(name, group))
  const released = group ? [...packages.keys()].filter((packageName) => isInGroup(packageName, group)) : [name]
  const isReleased = (release) => released.includes(release.name)

  const changesets = await readChangesets()
  const pendingChangesets = (packageName) =>
    changesets.filter((changeset) => changeset.releases.some((release) => release.name === packageName))

  if (!released.some((packageName) => pendingChangesets(packageName).length > 0)) {
    throw new Error(`There are no changesets for ${released.join(', ')}`)
  }

  // The released packages depend on the version of the workspace packages that is on npm. A pending changeset means
  // that the workspace has changes that aren't on npm, which the released packages might use.
  for (const packageName of released) {
    const { dependencies, peerDependencies, optionalDependencies } = packages.get(packageName)
    for (const [dependency, range] of Object.entries({
      ...dependencies,
      ...peerDependencies,
      ...optionalDependencies,
    })) {
      if (!range.startsWith('workspace:') || released.includes(dependency)) {
        continue
      }

      const files = pendingChangesets(dependency).map(({ file }) => file)
      if (files.length > 0) {
        throw new Error(
          `${packageName} depends on ${dependency}, which has changesets that aren't released: ${files.join(', ')}. Release ${dependency} first.`
        )
      }
    }
  }

  // `changeset version` consumes all changesets, so the other changesets are set aside while it runs. It also commits
  // because of the `commit` option, without the changesets that were set aside. The commit is undone, so that the
  // release workflow commits the versions together with the changesets that stay pending.
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()
  const otherChangesets = changesets.filter((changeset) => !changeset.releases.every(isReleased))
  let isVersioned = false
  try {
    for (const changeset of otherChangesets) {
      const releases = changeset.releases.filter(isReleased)
      if (releases.length > 0) {
        await writeFile(changeset.path, formatChangeset(releases, changeset.summary))
      } else {
        await rm(changeset.path)
      }
    }

    execFileSync('pnpm', ['changeset-version'], { stdio: 'inherit' })
    isVersioned = true
  } finally {
    for (const changeset of otherChangesets) {
      const releases = changeset.releases.filter((release) => !isReleased(release))
      const isConsumed = isVersioned && releases.length < changeset.releases.length
      await writeFile(changeset.path, isConsumed ? formatChangeset(releases, changeset.summary) : changeset.content)
    }

    execFileSync('git', ['reset', '--quiet', head])
  }

  // changesets also bumps the packages that depend on a released package with a range the new version is outside of.
  // They would be published with their unreleased changes.
  const versionedPackages = await readPackages()
  const unexpected = [...versionedPackages.keys()].filter(
    (packageName) =>
      !released.includes(packageName) &&
      versionedPackages.get(packageName).version !== packages.get(packageName).version
  )
  if (unexpected.length > 0) {
    throw new Error(
      `Versioning ${name} also bumped ${unexpected.join(', ')}, because they depend on a package that is released with it`
    )
  }

  const version = versionedPackages.get(name).version
  console.log(`Versioned ${released.join(', ')} to ${version}`)
  if (process.env.GITHUB_OUTPUT) {
    await appendFile(process.env.GITHUB_OUTPUT, `version=${version}\npackages=${released.join(' ')}\n`)
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error)
  process.exit(1)
})
