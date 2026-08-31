/**
 * WRPRC wire dialects
 *
 * ETSI TS 119 475 v1.2.1 names the array of claim queries `claim` and the intermediary
 * common name `sname`. Both read as editorial defects that a later edition is expected to
 * correct. Parsing accepts either spelling; serialization emits the published edition
 * unless a dialect is chosen explicitly.
 *
 * @see https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf
 */

import type { WRPRCPayload } from './types'

/**
 * Wire dialects understood by this package.
 */
export const WRPRC_DIALECTS = {
  /** ETSI TS 119 475 v1.2.1 as published. The default for everything this package emits. */
  CURRENT: 'ts119475-1.2.1',
  /**
   * Anticipated corrections: `claims` instead of `claim`, `intermediary.name` instead of
   * `intermediary.sname`.
   *
   * Unstable. No published edition defines this yet, so a certificate emitted in this
   * dialect may match neither the current specification nor its eventual correction.
   */
  DRAFT: 'draft',
} as const

/** A wire dialect understood by this package */
export type WRPRCDialect = (typeof WRPRC_DIALECTS)[keyof typeof WRPRC_DIALECTS]

type Record_ = Record<string, unknown>

function isRecord(value: unknown): value is Record_ {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Rename a key, leaving the value alone if the target name is already taken. */
function renameKey(value: unknown, from: string, to: string): unknown {
  if (!isRecord(value) || !(from in value) || to in value) return value
  const { [from]: moved, ...rest } = value
  return { ...rest, [to]: moved }
}

function renameInCredentials(value: unknown, from: string, to: string): unknown {
  if (!Array.isArray(value)) return value
  return value.map((entry) => renameKey(entry, from, to))
}

function mapPayload(payload: unknown, claimFrom: string, claimTo: string, nameFrom: string, nameTo: string): unknown {
  if (!isRecord(payload)) return payload
  const result: Record_ = { ...payload }
  if ('credentials' in result) {
    result.credentials = renameInCredentials(result.credentials, claimFrom, claimTo)
  }
  if ('provides_attestations' in result) {
    result.provides_attestations = renameInCredentials(result.provides_attestations, claimFrom, claimTo)
  }
  if ('intermediary' in result) {
    result.intermediary = renameKey(result.intermediary, nameFrom, nameTo)
  }
  return result
}

/**
 * Accept the anticipated `claims` and `intermediary.name` spellings when parsing, so a
 * certificate from an SDK that already applies the corrections still validates.
 */
export function normalizeWRPRCPayload(payload: unknown): unknown {
  return mapPayload(payload, 'claims', 'claim', 'name', 'sname')
}

/**
 * Serialize a canonical payload in the requested dialect.
 */
export function toWRPRCDialect(payload: WRPRCPayload, dialect: WRPRCDialect): unknown {
  if (dialect === WRPRC_DIALECTS.CURRENT) return payload
  return mapPayload(payload, 'claim', 'claims', 'sname', 'name')
}
