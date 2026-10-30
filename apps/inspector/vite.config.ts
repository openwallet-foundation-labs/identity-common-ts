import { resolve } from 'node:path'
import { defineConfig } from 'vite'
import { layout } from './layout'
import { PAGES } from './src/site'

export default defineConfig({
  // A relative base, so the build works under any path, e.g. /inspector/ on GitHub Pages
  base: './',
  appType: 'mpa',
  plugins: [layout()],
  build: {
    // The page that recognises any document loads the parsers of a format when it needs them
    chunkSizeWarningLimit: 1024,
    rolldownOptions: {
      input: {
        index: resolve(import.meta.dirname, 'index.html'),
        ...Object.fromEntries(PAGES.map((page) => [page.id, resolve(import.meta.dirname, page.id, 'index.html')])),
      },
    },
  },
})
