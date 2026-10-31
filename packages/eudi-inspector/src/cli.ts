#!/usr/bin/env node
import { stderr, stdin, stdout } from 'node:process'
import { run } from './cli-run'

// Set when the command line tool is built, see tsdown.config.mts
declare const __INSPECTOR_VERSION__: string | undefined

async function readStdin(): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  for await (const chunk of stdin) chunks.push(chunk)
  return new Uint8Array(Buffer.concat(chunks))
}

process.exitCode = await run(process.argv.slice(2), {
  stdout: (text) => stdout.write(`${text}\n`),
  stderr: (text) => stderr.write(`${text}\n`),
  readStdin,
  fetch: globalThis.fetch,
  // The command line tool is where the crypto implementation is chosen: the one of Node.js
  crypto: globalThis.crypto,
  color: stdout.isTTY && !process.env.NO_COLOR,
  version: typeof __INSPECTOR_VERSION__ === 'string' ? __INSPECTOR_VERSION__ : 'development',
})
