import { readFileSync } from 'node:fs'
import { defineConfig } from 'tsdown'

const { version } = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'))
const define = { __INSPECTOR_VERSION__: JSON.stringify(version) }

export default defineConfig([
  // The library, and the command line tool that runs on Node.js with the dependencies installed
  {
    entry: ['src/index.ts', 'src/cli.ts'],
    format: 'esm',
    dts: true,
    sourcemap: true,
    define,
  },
])
