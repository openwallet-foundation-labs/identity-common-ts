/**
 * Make the examples of the pages into src/examples/, see scripts/examples.ts.
 *
 * The examples are loaded through Vite, which reads the packages from their TypeScript
 * sources as the tests do.
 */
import { execFileSync } from 'node:child_process'
import { mkdir, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { createServer } from 'vite'

const root = fileURLToPath(new URL('..', import.meta.url))
const outDir = new URL('../src/examples/', import.meta.url)
const HEADER =
  '// Made by scripts/generate-examples.mjs, run `pnpm --filter identity-inspector examples` to make it again\n'

const server = await createServer({
  root,
  configFile: false,
  appType: 'custom',
  logLevel: 'error',
  server: { middlewareMode: true, hmr: false, ws: false },
})
try {
  const { generateExamples } = await server.ssrLoadModule('/scripts/examples.ts')
  const { pages, featured } = await generateExamples()
  await mkdir(outDir, { recursive: true })
  for (const [page, examples] of Object.entries(pages)) {
    await writeFile(
      new URL(`${page}.ts`, outDir),
      `${HEADER}import type { Example } from '../example'\n\nexport const examples: Example[] = ${JSON.stringify(examples, null, 2)}\n`
    )
  }
  await writeFile(
    new URL('featured.ts', outDir),
    `${HEADER}import type { FeaturedExample } from '../example'\n\nexport const featured: FeaturedExample[] = ${JSON.stringify(featured, null, 2)}\n`
  )
} finally {
  await server.close()
}
execFileSync('pnpm', ['exec', 'biome', 'check', '--write', '--unsafe', fileURLToPath(outDir)], { stdio: 'inherit' })
