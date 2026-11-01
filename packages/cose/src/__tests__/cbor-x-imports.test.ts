import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, test } from 'vitest'

const sourceDirectory = join(__dirname, '..')

const sourceFiles = (directory: string): string[] =>
  readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) return entry.name === '__tests__' ? [] : sourceFiles(path)
    return entry.name.endsWith('.ts') && !entry.name.endsWith('.test.ts') ? [path] : []
  })

const bareCborXImport =
  /(?:^|[\n;])\s*(?:import|export)\s+(?!type\s)(?:[^;'"]*?\sfrom\s+)?['"]cbor-x['"]|(?:require|import)\(\s*['"]cbor-x['"]\s*\)/

describe('cbor-x imports', () => {
  test('source files only import cbor-x through its pure JS subpaths at runtime', () => {
    const offending = sourceFiles(sourceDirectory)
      .filter((file) => bareCborXImport.test(readFileSync(file, 'utf8')))
      .map((file) => relative(sourceDirectory, file))

    expect(offending).toEqual([])
  })

  test.each([
    ["import { Tag } from 'cbor-x'", true],
    ["export { Encoder } from 'cbor-x'", true],
    ["import 'cbor-x'", true],
    ["const cbor = await import('cbor-x')", true],
    ["import type { Tag } from 'cbor-x'", false],
    ["export type { Options } from 'cbor-x'", false],
    ["import { Encoder } from 'cbor-x/encode'", false],
  ])('detects %s as a runtime import: %s', (source, expected) => {
    expect(bareCborXImport.test(source)).toBe(expected)
  })
})
