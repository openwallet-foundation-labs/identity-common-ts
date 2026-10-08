import { AsnConvert } from '@peculiar/asn1-schema'
import { QCStatement, QCStatements } from '@peculiar/asn1-x509-qualified'
import { PdsLocation, QcCClegislation, QcEuPDS, QcType } from '@peculiar/asn1-x509-qualified-etsi'
import { QC_STATEMENTS, QC_TYPES, type QcType as QcTypeName } from './constants'
import type { QcStatements } from './types'
import { X509Exception } from './x509-exception'

const QC_TYPE_BY_OID = new Map<string, QcTypeName>(
  Object.entries(QC_TYPES).map(([name, oid]) => [oid, name as QcTypeName])
)

/** Decode the statementInfo of a statement with its ETSI EN 319 412-5 schema. */
function statementInfo<T>(statement: QCStatement, type: new () => T): T {
  if (!statement.statementInfo) {
    throw new X509Exception(`QCStatement ${statement.statementId} is missing its statementInfo`)
  }
  try {
    return AsnConvert.parse(statement.statementInfo, type)
  } catch (error) {
    throw new X509Exception(`Invalid statementInfo for QCStatement ${statement.statementId}`, error)
  }
}

/** Convert a decoded QCStatements extension (RFC 3739, ETSI EN 319 412-5). */
export function parseQcStatements(statements: QCStatements): QcStatements {
  const result: QcStatements = {
    statementIds: [],
    qcCompliance: false,
    qcSSCD: false,
    qcTypes: [],
    pds: [],
    legislationCountries: [],
  }

  for (const statement of statements) {
    result.statementIds.push(statement.statementId)

    switch (statement.statementId) {
      case QC_STATEMENTS.qcCompliance:
        result.qcCompliance = true
        break
      case QC_STATEMENTS.qcSSCD:
        result.qcSSCD = true
        break
      case QC_STATEMENTS.qcType:
        for (const oid of statementInfo(statement, QcType)) {
          result.qcTypes.push(QC_TYPE_BY_OID.get(oid) ?? oid)
        }
        break
      case QC_STATEMENTS.qcPDS:
        for (const { url, language } of statementInfo(statement, QcEuPDS)) {
          result.pds.push({ url, language })
        }
        break
      case QC_STATEMENTS.qcCClegislation:
        result.legislationCountries.push(...statementInfo(statement, QcCClegislation))
        break
    }
  }
  return result
}

export interface QcStatementsInput {
  qcTypes: QcTypeName[]
  qcSSCD?: boolean
  pds?: { url: string; language: string }[]
  legislationCountries?: string[]
}

function statement(statementId: string, info?: unknown): QCStatement {
  return Object.assign(new QCStatement(), {
    statementId,
    statementInfo: info === undefined ? undefined : AsnConvert.serialize(info),
  })
}

/** Build a QCStatements extension value with QcCompliance and the given statements. */
export function toQcStatements(input: QcStatementsInput): QCStatements {
  const statements = new QCStatements([statement(QC_STATEMENTS.qcCompliance)])

  if (input.qcSSCD) {
    statements.push(statement(QC_STATEMENTS.qcSSCD))
  }
  if (input.qcTypes.length > 0) {
    statements.push(statement(QC_STATEMENTS.qcType, new QcType(input.qcTypes.map((t) => QC_TYPES[t]))))
  }
  if (input.pds?.length) {
    statements.push(statement(QC_STATEMENTS.qcPDS, new QcEuPDS(input.pds.map((p) => new PdsLocation(p)))))
  }
  if (input.legislationCountries?.length) {
    statements.push(statement(QC_STATEMENTS.qcCClegislation, new QcCClegislation(input.legislationCountries)))
  }
  return statements
}
