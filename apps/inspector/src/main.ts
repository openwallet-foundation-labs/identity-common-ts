import './style.css'
import { type Inspection, InspectionError, inspect } from './inspect'
import { checkRequest } from './over-asking'
import { formatPath } from './paths'
import { DocumentTree, el, findingElement, placeFindings } from './tree'

const byId = <T extends HTMLElement>(id: string) => document.getElementById(id) as T

const source = byId<HTMLTextAreaElement>('source')
const urlForm = byId<HTMLFormElement>('url-form')
const urlInput = byId<HTMLInputElement>('url')
const fetchButton = byId<HTMLButtonElement>('fetch')
const fileInput = byId<HTMLInputElement>('file')
const inputPanel = byId<HTMLElement>('input-panel')
const errorPanel = byId<HTMLElement>('error')
const result = byId<HTMLElement>('result')
const summary = byId<HTMLElement>('summary')
const findingsTitle = byId<HTMLElement>('findings-title')
const findingsList = byId<HTMLElement>('findings')
const treeContainer = byId<HTMLElement>('tree')
const overAskingPanel = byId<HTMLElement>('over-asking-panel')
const requestInput = byId<HTMLTextAreaElement>('request')
const registrationInput = byId<HTMLTextAreaElement>('registration')
const modeTabs = [byId<HTMLButtonElement>('mode-inspect'), byId<HTMLButtonElement>('mode-over-asking')]

// Counts the inspections, so a late signature result does not land on a newer one
let run = 0

function showError(...content: (string | Node)[]): void {
  result.hidden = true
  errorPanel.replaceChildren(...content)
  errorPanel.hidden = false
}

function show(input: string | Uint8Array, origin: string): void {
  showResult(() => inspect(input), origin)
}

function showResult(produce: () => Inspection, origin: string): void {
  run++
  errorPanel.hidden = true
  let inspection: Inspection
  try {
    inspection = produce()
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    showError(error instanceof InspectionError ? message : `Unexpected error: ${message}`)
    return
  }
  render(inspection, origin)
}

function render(inspection: Inspection, origin: string): void {
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
  fact('Source', origin)
  fact('Checked', inspection.checks.join(', '))
  for (const [term, detail] of inspection.facts ?? []) fact(term, detail)
  if (inspection.notes.length > 0) {
    const notes = el('ul', 'notes')
    notes.append(...inspection.notes.map((note) => el('li', undefined, note)))
    fact('Not checked', notes)
  }
  if (inspection.verifySignature) {
    const signature = fact('Signature', el('span', 'pending', 'Verifying…'))
    const current = run
    inspection.verifySignature().then(
      (description) => {
        if (current === run) signature.replaceChildren(el('span', 'signature ok', description))
      },
      (error: unknown) => {
        const message = error instanceof Error ? error.message : String(error)
        if (current === run) signature.replaceChildren(el('span', 'signature bad', `Invalid: ${message}`))
      }
    )
  }
  summary.replaceChildren(el('h2', undefined, inspection.title), verdict, facts)
  if (inspection.lookup) summary.append(lookupForm(inspection.lookup))

  findingsTitle.textContent = `Findings (${findings.length})`
  findingsList.replaceChildren(
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
  treeContainer.replaceChildren(tree.element)
  result.hidden = false
}

function lookupForm({ label, placeholder, find }: NonNullable<Inspection['lookup']>): HTMLElement {
  const form = el('form', 'lookup')
  const input = el('input')
  input.id = 'lookup'
  input.inputMode = 'numeric'
  input.placeholder = placeholder
  input.autocomplete = 'off'
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
  return form
}

function selectMode(mode: 'inspect' | 'over-asking'): void {
  for (const tab of modeTabs) tab.setAttribute('aria-selected', String(tab.id === `mode-${mode}`))
  inputPanel.hidden = mode !== 'inspect'
  overAskingPanel.hidden = mode !== 'over-asking'
  result.hidden = true
  errorPanel.hidden = true
  history.replaceState(null, '', mode === 'inspect' ? location.pathname : '#over-asking')
}

for (const tab of modeTabs) {
  tab.addEventListener('click', () => selectMode(tab.id === 'mode-over-asking' ? 'over-asking' : 'inspect'))
}
if (location.hash === '#over-asking') selectMode('over-asking')

const check = () => showResult(() => checkRequest(requestInput.value, registrationInput.value), 'Pasted request')
byId<HTMLButtonElement>('check').addEventListener('click', check)
for (const textarea of [requestInput, registrationInput]) {
  textarea.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
      event.preventDefault()
      check()
    }
  })
}

async function showFile(file: File): Promise<void> {
  show(new Uint8Array(await file.arrayBuffer()), `File ${file.name} (${file.size.toLocaleString()} bytes)`)
}

byId<HTMLButtonElement>('inspect').addEventListener('click', () => show(source.value, 'Pasted content'))
source.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
    event.preventDefault()
    show(source.value, 'Pasted content')
  }
})

byId<HTMLButtonElement>('choose-file').addEventListener('click', () => fileInput.click())
fileInput.addEventListener('change', () => {
  const file = fileInput.files?.[0]
  if (file) void showFile(file)
  fileInput.value = ''
})

inputPanel.addEventListener('dragover', (event) => {
  event.preventDefault()
  inputPanel.classList.add('dragging')
})
inputPanel.addEventListener('dragleave', (event) => {
  if (!inputPanel.contains(event.relatedTarget as Node | null)) inputPanel.classList.remove('dragging')
})
inputPanel.addEventListener('drop', (event) => {
  event.preventDefault()
  inputPanel.classList.remove('dragging')
  const file = event.dataTransfer?.files[0]
  if (file) {
    void showFile(file)
    return
  }
  const text = event.dataTransfer?.getData('text/plain')
  if (text) {
    source.value = text
    show(text, 'Dropped text')
  }
})

urlForm.addEventListener('submit', async (event) => {
  event.preventDefault()
  let url: URL
  try {
    url = new URL(urlInput.value.trim())
  } catch {
    showError('This is not a valid URL.')
    return
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    showError('Only http and https URLs can be fetched.')
    return
  }

  fetchButton.disabled = true
  fetchButton.textContent = 'Fetching…'
  try {
    const response = await fetch(url, { credentials: 'omit' })
    if (!response.ok) {
      showError(`The server answered ${response.status} ${response.statusText}.`)
      return
    }
    show(new Uint8Array(await response.arrayBuffer()), url.href)
  } catch {
    // A failed fetch does not say why; a missing CORS header is the common cause
    const link = el('a', undefined, 'Open the URL')
    link.href = url.href
    link.target = '_blank'
    link.rel = 'noopener noreferrer'
    showError(
      `${url.href} could not be fetched. The server may not allow requests from other websites (CORS), or it is unreachable. `,
      link,
      ', download the document and drop it here instead.'
    )
  } finally {
    fetchButton.disabled = false
    fetchButton.textContent = 'Fetch'
  }
})
