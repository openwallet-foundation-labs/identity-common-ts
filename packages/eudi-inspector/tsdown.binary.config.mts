import { readFileSync } from 'node:fs'
import { defineConfig } from 'tsdown'

const { version } = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'))

// The command line tool as a single executable of Node.js (SEA), with every dependency bundled.
// Build it with Node.js 25.7 or later; the executable is for the platform it is built on.
export default defineConfig({
  entry: { 'eudi-inspect': 'src/cli.ts' },
  format: 'esm',
  platform: 'node',
  outDir: 'dist-binary/bundle',
  dts: false,
  define: { __INSPECTOR_VERSION__: JSON.stringify(version) },
  deps: { alwaysBundle: [/./], onlyBundle: false },
  exe: { outDir: 'dist-binary', fileName: 'eudi-inspect' },
})
