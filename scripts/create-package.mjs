#!/usr/bin/env node

/**
 * Script to generate a new package in the monorepo
 *
 * Usage: node scripts/create-package.mjs <package-name> [--eudi]
 *
 * Examples:
 *   node scripts/create-package.mjs jose
 *   node scripts/create-package.mjs eudi-lote --eudi
 */

import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const args = process.argv.slice(2)
const packageName = args[0]
const isEudi = args.includes('--eudi')

if (!packageName) {
  console.error('Usage: node scripts/create-package.mjs <package-name> [--eudi]')
  console.error('')
  console.error('Examples:')
  console.error('  node scripts/create-package.mjs jose')
  console.error('  node scripts/create-package.mjs eudi-lote --eudi')
  process.exit(1)
}

// Validate package name
if (!/^[a-z][a-z0-9-]*$/.test(packageName)) {
  console.error(
    'Package name must start with a lowercase letter and contain only lowercase letters, numbers, and hyphens'
  )
  process.exit(1)
}

const fullPackageName = isEudi ? `@owf/eudi-${packageName.replace(/^eudi-/, '')}` : `@owf/${packageName}`
const packageDir = join(process.cwd(), 'packages', packageName)

console.log(`Creating package: ${fullPackageName}`)
console.log(`Directory: ${packageDir}`)
console.log('')

// Package.json template
const packageJson = {
  name: fullPackageName,
  version: '0.0.0',
  description: `TODO: Add description for ${fullPackageName}`,
  files: ['dist'],
  license: 'Apache-2.0',
  exports: './src/index.ts',
  homepage: `https://github.com/openwallet-foundation-labs/identity-common-ts/tree/main/packages/${packageName}`,
  repository: {
    type: 'git',
    url: 'https://github.com/openwallet-foundation-labs/identity-common-ts',
    directory: `packages/${packageName}`,
  },
  publishConfig: {
    module: './dist/index.mjs',
    types: './dist/index.d.mts',
    exports: {
      '.': './dist/index.mjs',
      './package.json': './package.json',
    },
  },
  scripts: {
    build: 'tsdown src/index.ts --format esm --dts --sourcemap',
  },
  dependencies: {},
  devDependencies: {},
}

// tsconfig.json template
const tsconfigJson = {
  extends: '../../tsconfig.json',
  compilerOptions: {
    outDir: 'dist',
    rootDir: 'src',
  },
  include: ['src'],
}

// README template
const readme = `# ${fullPackageName}

[![npm version](https://img.shields.io/npm/v/${fullPackageName})](https://npmjs.com/package/${fullPackageName})
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE)

${isEudi ? 'EUDI-specific tools' : 'Core identity utilities'} for [Identity Common TypeScript](https://github.com/openwallet-foundation-labs/identity-common-ts).

## Installation

\`\`\`bash
# Using npm
npm install ${fullPackageName}

# Using pnpm
pnpm add ${fullPackageName}

# Using yarn
yarn add ${fullPackageName}
\`\`\`

## Usage

\`\`\`typescript
import { } from '${fullPackageName}'
\`\`\`

## Platform Support

This library is **platform agnostic** and works in:

- ✅ Node.js (>=22)
- ✅ Browsers (modern browsers with ES2020 support)
- ✅ React Native

## API Reference

*TODO: Add API documentation*

## Contributing

See the [Contributing Guide](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the [Apache License Version 2.0](https://github.com/openwallet-foundation-labs/identity-common-ts/blob/main/LICENSE) (Apache-2.0).
`

// Index.ts template
const indexTs = `/**
 * ${fullPackageName}
 *
 * ${isEudi ? 'EUDI-specific tools' : 'Core identity utilities'} for identity applications.
 *
 * @packageDocumentation
 */

// Export your public API here
export {}
`

// Test file template
const testFile = `import { describe, it, expect } from 'vitest'

describe('${packageName}', () => {
  it('should be tested', () => {
    // TODO: Add tests
    expect(true).toBe(true)
  })
})
`

async function main() {
  try {
    // Create directories
    await mkdir(join(packageDir, 'src', '__tests__'), { recursive: true })

    // Write files
    await writeFile(join(packageDir, 'package.json'), `${JSON.stringify(packageJson, null, 2)}\n`)
    await writeFile(join(packageDir, 'tsconfig.json'), `${JSON.stringify(tsconfigJson, null, 2)}\n`)
    await writeFile(join(packageDir, 'README.md'), readme)
    await writeFile(join(packageDir, 'src', 'index.ts'), indexTs)
    await writeFile(join(packageDir, 'src', '__tests__', `${packageName}.test.mts`), testFile)

    console.log('✅ Package created successfully!')
    console.log('')
    console.log('Next steps:')
    console.log(`  1. Update the description in packages/${packageName}/package.json`)
    console.log(`  2. Add your code to packages/${packageName}/src/index.ts`)
    console.log(`  3. Add tests to packages/${packageName}/src/__tests__/`)
    console.log('  4. Run: pnpm install')
    console.log('  5. Run: pnpm build')
    console.log('  6. Run: pnpm test')
    console.log('')
  } catch (error) {
    console.error('Error creating package:', error)
    process.exit(1)
  }
}

main()
