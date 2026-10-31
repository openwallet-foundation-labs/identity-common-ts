import { formatPath } from './paths'
import type { InspectionReport } from './report'

// The report as text for a terminal

export interface TextOptions {
  /** Where the document came from */
  source?: string
  /** Use ANSI colors */
  color?: boolean
  /** Further lines of facts, e.g. the status looked up at an index */
  extra?: [string, string][]
}

const STYLES = { bold: 1, dim: 2, red: 31, green: 32, yellow: 33 } as const

type Style = keyof typeof STYLES

function styler(color: boolean) {
  return (style: Style, text: string) => (color ? `\u001b[${STYLES[style]}m${text}\u001b[0m` : text)
}

const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? '' : 's'}`

/** The verdict of a report, e.g. "2 errors, 1 warning" */
export function verdict(report: InspectionReport): string {
  const errors = report.findings.filter((finding) => finding.severity === 'error').length
  const warnings = report.findings.length - errors
  const invalid = report.signatures.filter((signature) => signature.status === 'invalid').length
  const parts = [
    ...(errors ? [plural(errors, 'error')] : []),
    ...(warnings ? [plural(warnings, 'warning')] : []),
    ...(invalid ? [`${plural(invalid, 'invalid signature')}`] : []),
  ]
  return parts.length > 0 ? parts.join(', ') : 'No errors or warnings'
}

/** The report as lines of text: the verdict, the facts, the signatures, and each finding with its path */
export function formatReport(report: InspectionReport, options: TextOptions = {}): string {
  const style = styler(options.color ?? false)
  const lines: string[] = []

  const ok = report.valid && report.findings.length === 0
  lines.push(
    `${style('bold', report.title)}  ${style(report.valid ? (ok ? 'green' : 'yellow') : 'red', verdict(report))}`
  )

  const rows: [string, string, Style?][] = []
  if (options.source) rows.push(['Source', options.source])
  rows.push(['Checked', report.checks.join(', ')])
  for (const [label, value] of Object.entries(report.facts)) rows.push([label, value])
  for (const [label, value] of options.extra ?? []) rows.push([label, value])
  for (const { label, status, message } of report.signatures) {
    rows.push([label, message, status === 'valid' ? 'green' : status === 'invalid' ? 'red' : 'yellow'])
  }
  report.notes.forEach((note, index) => {
    rows.push([index === 0 ? 'Not checked' : '', note, 'dim'])
  })
  const width = Math.max(...rows.map(([label]) => label.length))
  for (const [label, value, valueStyle] of rows) {
    const text = valueStyle ? style(valueStyle, value) : value
    lines.push(`  ${style('dim', label.padEnd(width))}  ${text}`)
  }

  if (report.findings.length > 0) {
    lines.push('')
    // Errors first, as in the web page
    const findings = [...report.findings].sort(
      (a, b) => Number(b.severity === 'error') - Number(a.severity === 'error')
    )
    for (const finding of findings) {
      const severity = finding.severity === 'error' ? style('red', 'error  ') : style('yellow', 'warning')
      const requirement = finding.requirement ? style('dim', ` (${finding.requirement})`) : ''
      lines.push(`  ${severity}  ${style('bold', finding.code)} at ${formatPath(finding.path)}${requirement}`)
      lines.push(`           ${finding.message}`)
    }
  }
  return lines.join('\n')
}
