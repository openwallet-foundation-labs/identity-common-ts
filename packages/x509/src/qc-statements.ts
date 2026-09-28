import * as asn1js from 'asn1js'
import { QC_STATEMENTS, QC_TYPES, type QcType } from './constants'
import { asn1ToString, parseDer } from './der'
import type { QcStatements } from './types'
import { X509Exception } from './x509-exception'

const QC_TYPE_BY_OID = new Map<string, QcType>(Object.entries(QC_TYPES).map(([name, oid]) => [oid, name as QcType]))

function children(node: asn1js.AsnType | undefined): asn1js.AsnType[] {
  return node instanceof asn1js.Sequence ? node.valueBlock.value : []
}

/** Parse the QCStatements extension value (RFC 3739, ETSI EN 319 412-5). */
export function parseQcStatements(extnValue: Uint8Array): QcStatements {
  const root = parseDer(extnValue)
  if (!(root instanceof asn1js.Sequence)) {
    throw new X509Exception('QCStatements must be a SEQUENCE')
  }
  const result: QcStatements = {
    statementIds: [],
    qcCompliance: false,
    qcSSCD: false,
    qcTypes: [],
    pds: [],
    legislationCountries: [],
  }

  for (const statement of root.valueBlock.value) {
    const [id, info] = children(statement)
    if (!(id instanceof asn1js.ObjectIdentifier)) {
      throw new X509Exception('QCStatement is missing its statementId')
    }
    const statementId = id.valueBlock.toString()
    result.statementIds.push(statementId)

    switch (statementId) {
      case QC_STATEMENTS.qcCompliance:
        result.qcCompliance = true
        break
      case QC_STATEMENTS.qcSSCD:
        result.qcSSCD = true
        break
      case QC_STATEMENTS.qcType:
        for (const type of children(info)) {
          if (type instanceof asn1js.ObjectIdentifier) {
            const oid = type.valueBlock.toString()
            result.qcTypes.push(QC_TYPE_BY_OID.get(oid) ?? oid)
          }
        }
        break
      case QC_STATEMENTS.qcPDS:
        for (const location of children(info)) {
          const [url, language] = children(location)
          const urlString = url && asn1ToString(url)
          const languageString = language && asn1ToString(language)
          if (urlString && languageString) result.pds.push({ url: urlString, language: languageString })
        }
        break
      case QC_STATEMENTS.qcCClegislation:
        for (const country of children(info)) {
          const code = asn1ToString(country)
          if (code) result.legislationCountries.push(code)
        }
        break
    }
  }
  return result
}

export interface QcStatementsInput {
  qcTypes: QcType[]
  qcSSCD?: boolean
  pds?: { url: string; language: string }[]
  legislationCountries?: string[]
}

/** Encode a QCStatements extension value with QcCompliance and the given statements. */
export function encodeQcStatements(input: QcStatementsInput): Uint8Array {
  const oid = (value: string) => new asn1js.ObjectIdentifier({ value })
  const statements: asn1js.Sequence[] = [new asn1js.Sequence({ value: [oid(QC_STATEMENTS.qcCompliance)] })]

  if (input.qcSSCD) {
    statements.push(new asn1js.Sequence({ value: [oid(QC_STATEMENTS.qcSSCD)] }))
  }
  if (input.qcTypes.length > 0) {
    statements.push(
      new asn1js.Sequence({
        value: [oid(QC_STATEMENTS.qcType), new asn1js.Sequence({ value: input.qcTypes.map((t) => oid(QC_TYPES[t])) })],
      })
    )
  }
  if (input.pds?.length) {
    statements.push(
      new asn1js.Sequence({
        value: [
          oid(QC_STATEMENTS.qcPDS),
          new asn1js.Sequence({
            value: input.pds.map(
              (p) =>
                new asn1js.Sequence({
                  value: [new asn1js.IA5String({ value: p.url }), new asn1js.PrintableString({ value: p.language })],
                })
            ),
          }),
        ],
      })
    )
  }
  if (input.legislationCountries?.length) {
    statements.push(
      new asn1js.Sequence({
        value: [
          oid(QC_STATEMENTS.qcCClegislation),
          new asn1js.Sequence({
            value: input.legislationCountries.map((c) => new asn1js.PrintableString({ value: c })),
          }),
        ],
      })
    )
  }

  return new Uint8Array(new asn1js.Sequence({ value: statements }).toBER())
}
