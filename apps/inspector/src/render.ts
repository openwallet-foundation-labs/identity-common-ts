import type { Inspection, SignatureResult } from './inspection'
import { formatPath } from './paths'
import { DocumentTree, el, findingElement, placeFindings } from './tree'

const byId = <T extends HTMLElement>(id: string) => document.getElementById(id) as T

export interface RenderOptions {
  /** Where the document came from */
  origin: string
  /** Elements to add at the end of the summary, e.g. a button to copy a link */
  actions?: HTMLElement[]
  /** Content between the summary and the findings */
  extra?: HTMLElement
  /** The value to look up right away */
  lookup?: string
}

// Counts the renderings, so a late signature result does not land on a newer one
let rendered = 0

export function hideResult(): void {
  rendered++
  byId('result').hidden = true
  byId('error').hidden = true
}

export function showError(...content: (string | Node)[]): void {
  hideResult()
  const error = byId('error')
  error.replaceChildren(...content)
  error.hidden = false
}

const SIGNATURE_CLASSES: Record<SignatureResult['status'], string> = {
  valid: 'signature ok',
  invalid: 'signature bad',
  unverified: 'signature unverified',
}

export function renderInspection(inspection: Inspection, options: RenderOptions): void {
  hideResult()
  const current = rendered
  const findings = placeFindings(inspection.value, inspection.findings).sort(
    (a, b) => Number(b.severity === 'error') - Number(a.severity === 'error')
  )
  const errors = findings.filter((finding) => finding.severity === 'error').length
  const warnings = findings.length - errors
  const tree = new DocumentTree(inspection.value, findings)

  const verdict = el('p', `verdict ${errors ? 'bad' : warnings ? 'warn' : 'ok'}`)
  verdict.textContent = errors
    ? `${errors} ${errors === 1 ? 'error' : 'errors'}${warnings ? `, ${warnings} ${warnings === 1 ? 'warning' : 'warnings'}` : ''}`
    : warnings
      ? `No errors, ${warnings} ${warnings === 1 ? 'warning' : 'warnings'}`
      : 'No errors or warnings'

  const facts = el('dl', 'facts')
  const fact = (term: string, ...details: (string | Node)[]) => {
    const dd = el('dd')
    dd.append(...details)
    facts.append(el('dt', undefined, term), dd)
    return dd
  }
  fact('Source', options.origin)
  fact('Checked', inspection.checks.join(', '))
  for (const [term, detail] of inspection.facts ?? []) fact(term, detail)
  for (const signature of inspection.signatures ?? []) {
    const detail = fact(signature.label, el('span', 'pending', 'Verifying…'))
    signature.verify().then(
      ({ status, message }) => {
        if (current === rendered) detail.replaceChildren(el('span', SIGNATURE_CLASSES[status], message))
      },
      (error: unknown) => {
        const message = error instanceof Error ? error.message : String(error)
        if (current === rendered) detail.replaceChildren(el('span', SIGNATURE_CLASSES.invalid, `Invalid: ${message}`))
      }
    )
  }
  if (inspection.notes.length > 0) {
    const notes = el('ul', 'notes')
    notes.append(...inspection.notes.map((note) => el('li', undefined, note)))
    fact('Not checked', notes)
  }

  const summary = byId('summary')
  summary.replaceChildren(el('h2', undefined, inspection.title), verdict, facts)
  if (inspection.lookup) summary.append(lookupForm(inspection.lookup, options.lookup))
  if (options.actions?.length) {
    const actions = el('div', 'summary-actions')
    actions.append(...options.actions)
    summary.append(actions)
  }
  byId('extra').replaceChildren(...(options.extra ? [options.extra] : []))

  byId('findings-title').textContent = `Findings (${findings.length})`
  byId('findings').replaceChildren(
    ...(findings.length === 0
      ? [el('p', 'empty-note', 'Every checked element conforms.')]
      : findings.map((finding) => {
          const item = el('button', 'finding-link')
          item.type = 'button'
          item.append(el('span', 'path', formatPath(finding.path)), findingElement(finding))
          item.addEventListener('click', () => tree.reveal(finding.anchor))
          return item
        }))
  )
  byId('tree').replaceChildren(tree.element)
  byId('result').hidden = false
}

function lookupForm({ label, placeholder, find }: NonNullable<Inspection['lookup']>, initial = ''): HTMLElement {
  const form = el('form', 'lookup')
  const input = el('input')
  input.id = 'lookup'
  input.inputMode = 'numeric'
  input.placeholder = placeholder
  input.autocomplete = 'off'
  input.value = initial
  const answer = el('output', 'lookup-answer')
  answer.htmlFor.add('lookup')
  const caption = el('label', undefined, label)
  caption.htmlFor = 'lookup'
  form.append(caption, input, answer)
  const update = () => {
    answer.textContent = input.value.trim() ? find(input.value) : ''
  }
  input.addEventListener('input', update)
  form.addEventListener('submit', (event) => {
    event.preventDefault()
    update()
  })
  update()
  return form
}
