import './style.css'
import {
  type DocumentFormat,
  type DocumentInput,
  detect,
  fromFragment,
  type Inspection,
  InspectionError,
  MAX_LINK_LENGTH,
  type SharedValue,
  toFragment,
} from '@owf/eudi-inspector'
import { base64url } from '@owf/identity-common'
import { renderInspection, showError } from './render'
import { pageOf } from './site'
import { el } from './tree'

export interface PageInput {
  /** The document, empty on a page without a document field */
  document: DocumentInput
  /** The values of the other fields of the form by name, "1" for a checked checkbox */
  fields: Record<string, string>
}

/** Lets a page link to the page of another format, carrying the document over */
export interface PageContext {
  linkTo: (format: DocumentFormat, text: string) => HTMLAnchorElement
}

export interface PageDefinition {
  /** The format of the page, to point to the right page when a document is of another */
  format?: DocumentFormat
  inspect: (input: PageInput) => Inspection | Promise<Inspection>
  /** Content between the summary and the findings */
  extra?: (inspection: Inspection, context: PageContext) => HTMLElement | undefined
  /** Elements to add to the summary */
  actions?: (inspection: Inspection, context: PageContext) => HTMLElement[]
}

/** A document that was not pasted: fetched, dropped, chosen or carried over from another page */
interface Loaded {
  document: DocumentInput
  origin: string
  url?: string
  /** What the document field shows of it, to tell whether it was edited since */
  shown: string
}

interface Handoff {
  text: string
  origin: string
  url?: string
}

type Field = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement

// Larger documents are not shown in the document field, which would become slow
const MAX_SHOWN = 1_000_000
const HANDOFF_KEY = 'inspector:handoff'

const root = document.body.dataset.root ?? './'

const errorMessage = (error: unknown) => (error instanceof Error ? error.message : String(error))

/** The URL of a page of the inspector, or of the page that recognises any document */
export const pageUrl = (id?: string) => new URL(id ? `${root}${id}/` : root, location.href).href

/** The bytes as text, if they are UTF-8 text */
function asText(bytes: Uint8Array): string | undefined {
  if (bytes.includes(0)) return undefined
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    return undefined
  }
}

/** The document as text, binary documents as base64url, which their pages read as well */
const documentText = (input: DocumentInput) =>
  typeof input === 'string' ? input : (asText(input) ?? base64url.encode(input))

function takeHandoff(): Handoff | undefined {
  try {
    const stored = sessionStorage.getItem(HANDOFF_KEY)
    sessionStorage.removeItem(HANDOFF_KEY)
    return stored ? (JSON.parse(stored) as Handoff) : undefined
  } catch {
    return undefined
  }
}

const isField = (element: Element): element is Field =>
  element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement

const fieldValue = (field: Field) =>
  field instanceof HTMLInputElement && field.type === 'checkbox' ? (field.checked ? '1' : '') : field.value

/**
 * Wire up a page: its document from a URL, a file, a drop or the document field, its other
 * fields, the result, and links that carry the input in the fragment.
 */
export function startPage(definition: PageDefinition): void {
  const byId = <T extends HTMLElement>(id: string) => document.getElementById(id) as T | null
  const form = byId<HTMLFormElement>('input-form')
  const panel = byId<HTMLElement>('input-panel')
  if (!form || !panel) throw new Error('The page has no input form')
  const docField = byId<HTMLTextAreaElement>('doc')
  const urlForm = byId<HTMLFormElement>('url-form')
  const urlInput = byId<HTMLInputElement>('url')
  const fetchButton = byId<HTMLButtonElement>('fetch')
  const fileInput = byId<HTMLInputElement>('file')

  // Where the navigation scrolls, on narrow screens, show the link of this page
  const nav = document.querySelector<HTMLElement>('.site-nav')
  const here = nav?.querySelector<HTMLElement>('[aria-current="page"]')
  if (nav && here) nav.scrollLeft = here.offsetLeft - nav.offsetLeft - (nav.clientWidth - here.offsetWidth) / 2

  let loaded: Loaded | undefined
  let runs = 0
  let pendingLookup: string | undefined

  const fields = () => [...form.elements].filter(isField).filter((field) => field.name && field !== docField)
  const compressed = new Set([...form.querySelectorAll('textarea')].map((textarea) => textarea.name))

  function current(): { document: DocumentInput; origin: string } {
    if (loaded && (!docField || docField.value === loaded.shown)) return loaded
    loaded = undefined
    return { document: docField?.value ?? '', origin: 'Pasted content' }
  }

  const context: PageContext = {
    linkTo(format, text) {
      const link = el('a', 'page-link', text)
      link.href = pageUrl(format)
      link.addEventListener('click', () => {
        const { document: input, origin } = current()
        const handoff: Handoff = { text: documentText(input), origin, url: loaded?.url }
        try {
          sessionStorage.setItem(HANDOFF_KEY, JSON.stringify(handoff))
        } catch {
          // Too large for the session storage: a fetched document can be fetched again
          if (handoff.url) link.href = `${pageUrl(format)}#${new URLSearchParams({ url: handoff.url })}`
        }
      })
      return link
    },
  }

  async function shareLink(): Promise<string | undefined> {
    const values: SharedValue[] = []
    if (docField) {
      const { document: input } = current()
      values.push(
        loaded?.url
          ? { name: 'url', value: loaded.url, compress: false }
          : { name: 'doc', value: documentText(input), compress: true }
      )
    }
    for (const field of fields()) {
      values.push({ name: field.name, value: fieldValue(field), compress: compressed.has(field.name) })
    }
    const lookup = byId<HTMLInputElement>('lookup')?.value.trim()
    if (lookup) values.push({ name: 'lookup', value: lookup, compress: false })
    const link = `${location.origin}${location.pathname}#${await toFragment(values)}`
    return link.length <= MAX_LINK_LENGTH ? link : undefined
  }

  function shareButton(): HTMLElement {
    const share = el('span', 'share')
    const button = el('button', undefined, 'Copy link to this result')
    button.type = 'button'
    const status = el('span', 'share-status')
    status.setAttribute('role', 'status')
    button.addEventListener('click', async () => {
      const link = await shareLink()
      if (!link) {
        status.textContent = 'The input is too large for a link. Share the URL of the document instead.'
        return
      }
      history.replaceState(null, '', link)
      try {
        await navigator.clipboard.writeText(link)
        status.textContent = 'Copied. Anyone with the link sees the input it holds.'
      } catch {
        status.textContent = 'The link is in the address bar. Anyone with it sees the input it holds.'
      }
    })
    share.append(button, status)
    return share
  }

  function showInspectionError(error: unknown, input: DocumentInput): void {
    if (!(error instanceof InspectionError)) {
      showError(`Unexpected error: ${errorMessage(error)}`)
      return
    }
    let other: DocumentFormat | undefined
    try {
      other = definition.format ? detect(input) : undefined
    } catch {
      // Not a format of another page either
    }
    const page = other && other !== definition.format ? pageOf(other) : undefined
    if (other && page) {
      showError(
        `${error.message.replace(/\.?$/, '.')} It is of another format: `,
        context.linkTo(other, `open it in the ${page.title}`),
        '.'
      )
    } else {
      showError(error.message)
    }
  }

  /** Inspect what the form holds. `fromLink` keeps the link the page was opened with in the address bar. */
  async function run(fromLink = false): Promise<void> {
    const run = ++runs
    const { document: input, origin } = current()
    if (!fromLink && location.hash) history.replaceState(null, '', location.pathname + location.search)
    let inspection: Inspection
    try {
      inspection = await definition.inspect({
        document: input,
        fields: Object.fromEntries(fields().map((field) => [field.name, fieldValue(field)])),
      })
    } catch (error) {
      if (run === runs) showInspectionError(error, input)
      return
    }
    if (run !== runs) return
    renderInspection(inspection, {
      // A page without a document field has only the fields, which the link filled in
      origin: fromLink && !docField ? 'Shared link' : origin,
      lookup: pendingLookup,
      extra: definition.extra?.(inspection, context),
      actions: [...(definition.actions?.(inspection, context) ?? []), shareButton()],
    })
    pendingLookup = undefined
  }

  function load(input: DocumentInput, origin: string, url?: string, fromLink = false): Promise<void> {
    const text = typeof input === 'string' ? input : asText(input)
    const shown = text !== undefined && text.length <= MAX_SHOWN ? text : ''
    loaded = { document: input, origin, url, shown }
    if (docField) docField.value = shown
    return run(fromLink)
  }

  async function fetchDocument(href: string, fromLink = false): Promise<void> {
    let url: URL
    try {
      url = new URL(href.trim())
    } catch {
      showError('This is not a valid URL.')
      return
    }
    if (url.protocol !== 'https:' && url.protocol !== 'http:') {
      showError('Only http and https URLs can be fetched.')
      return
    }

    let bytes: Uint8Array
    if (fetchButton) {
      fetchButton.disabled = true
      fetchButton.textContent = 'Fetching…'
    }
    try {
      const response = await fetch(url, { credentials: 'omit' })
      if (!response.ok) {
        showError(`The server answered ${response.status} ${response.statusText}.`)
        return
      }
      bytes = new Uint8Array(await response.arrayBuffer())
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
      return
    } finally {
      if (fetchButton) {
        fetchButton.disabled = false
        fetchButton.textContent = 'Fetch'
      }
    }
    await load(bytes, url.href, url.href, fromLink)
  }

  /** Take the input from another page, or from the fragment of a link */
  async function restore(): Promise<void> {
    const handoff = takeHandoff()
    if (handoff) {
      if (handoff.url && urlInput) urlInput.value = handoff.url
      await load(handoff.text, handoff.origin, handoff.url)
      return
    }
    if (!location.hash) return

    const values = await fromFragment(location.hash, compressed)
    for (const field of fields()) {
      const value = values.get(field.name) ?? ''
      if (field instanceof HTMLInputElement && field.type === 'checkbox') field.checked = value === '1'
      else field.value = value
    }
    pendingLookup = values.get('lookup')
    const url = values.get('url')
    const doc = values.get('doc')
    if (url && urlInput) {
      urlInput.value = url
      await fetchDocument(url, true)
    } else if (doc !== undefined && docField) {
      await load(doc, 'Shared link', undefined, true)
    } else if (!docField && values.size > 0) {
      await run(true)
    }
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault()
    void run()
  })
  form.addEventListener('keydown', (event) => {
    if (event.target instanceof HTMLTextAreaElement && event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
      event.preventDefault()
      void run()
    }
  })

  urlForm?.addEventListener('submit', (event) => {
    event.preventDefault()
    if (urlInput) void fetchDocument(urlInput.value)
  })

  const showFile = async (file: File) =>
    load(new Uint8Array(await file.arrayBuffer()), `File ${file.name} (${file.size.toLocaleString('en')} bytes)`)

  byId<HTMLButtonElement>('choose-file')?.addEventListener('click', () => fileInput?.click())
  fileInput?.addEventListener('change', () => {
    const file = fileInput.files?.[0]
    if (file) void showFile(file)
    fileInput.value = ''
  })

  if (docField) {
    panel.addEventListener('dragover', (event) => {
      event.preventDefault()
      panel.classList.add('dragging')
    })
    panel.addEventListener('dragleave', (event) => {
      if (!panel.contains(event.relatedTarget as Node | null)) panel.classList.remove('dragging')
    })
    panel.addEventListener('drop', (event) => {
      event.preventDefault()
      panel.classList.remove('dragging')
      const file = event.dataTransfer?.files[0]
      if (file) {
        void showFile(file)
        return
      }
      const text = event.dataTransfer?.getData('text/plain')
      if (text) void load(text, 'Dropped text')
    })
  }

  window.addEventListener('hashchange', () => void restore())
  void restore()
}
