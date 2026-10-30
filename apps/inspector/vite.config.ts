import { defineConfig } from 'vite'

export default defineConfig({
  // A relative base, so the build works under any path, e.g. /inspector/ on GitHub Pages
  base: './',
  build: {
    // The parsers, XML signature verification, ASN.1 and CBOR make one chunk of about 1 MB
    chunkSizeWarningLimit: 1536,
  },
})
