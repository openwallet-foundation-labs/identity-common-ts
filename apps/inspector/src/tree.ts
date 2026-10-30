import type { Finding } from '@owf/identity-common'
import { anchorOf, formatPath, type Path, pathKey } from './paths'

/** A finding together with where it is shown in the document */
export interface PlacedFinding extends Finding {
  /** The deepest element of the path that is present in the document */
  anchor: Path
  /** The rest of the path, naming an element that is not present */
  missing: Path
}

export function placeFindings(value: unknown, findings: Finding[]): PlacedFinding[] {
  return findings.map((finding) => ({ ...finding, ...anchorOf(value, finding.path) }))
}

/** Create an element. Text is always set as text, as the document is untrusted input. */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag)
  if (className) element.className = className
  if (text !== undefined) element.textContent = text
  return element
}

export function findingElement(finding: PlacedFinding): HTMLElement {
  const item = el('div', `finding ${finding.severity}`)
  const head = el('div', 'finding-head')
  head.append(
    el('span', 'severity', finding.severity === 'error' ? 'Error' : 'Warning'),
    el('code', 'code', finding.code)
  )
  if (finding.requirement) head.append(el('span', 'requirement', finding.requirement))
  item.append(head, el('p', 'message', finding.message))
  if (finding.missing.length > 0) item.append(el('p', 'missing', `${formatPath(finding.path)} is not present`))
  return item
}

interface Counts {
  errors: number
  warnings: number
}

const MAX_BYTES_SHOWN = 32
const MAX_TEXT_SHOWN = 160

const isContainer = (value: unknown): value is Record<string, unknown> | unknown[] =>
  typeof value === 'object' &&
  value !== null &&
  !(value instanceof Date) &&
  !(value instanceof ArrayBuffer) &&
  !ArrayBuffer.isView(value)

const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')

function formatLeaf(value: unknown): { text: string; kind: string } {
  if (value === undefined) return { text: 'not set', kind: 'empty' }
  if (value === null) return { text: 'null', kind: 'empty' }
  if (value instanceof Date) {
    return { text: Number.isNaN(value.getTime()) ? 'invalid date' : value.toISOString(), kind: 'date' }
  }
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    const bytes =
      value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    const more = bytes.length > MAX_BYTES_SHOWN ? '…' : ''
    return { text: `${bytes.length} bytes · ${toHex(bytes.subarray(0, MAX_BYTES_SHOWN))}${more}`, kind: 'bytes' }
  }
  if (typeof value === 'string') return { text: value, kind: 'string' }
  return { text: String(value), kind: typeof value }
}

// Properties that name an object well enough to find it in a collapsed list
const PREVIEW_KEYS = ['name', 'serviceName', 'TEName', 'ServiceName', 'commonName', 'sub', 'oid', 'type', 'uri']

function preview(value: Record<string, unknown> | unknown[]): string {
  if (Array.isArray(value)) return `[${value.length}]`
  for (const key of PREVIEW_KEYS) {
    const candidate = value[key]
    if (typeof candidate === 'string') return candidate
    // localized values, e.g. [{ lang: 'en', value: 'Name' }]
    const first = Array.isArray(candidate) ? candidate[0] : undefined
    if (typeof first === 'object' && first !== null && typeof (first as { value?: unknown }).value === 'string') {
      return (first as { value: string }).value
    }
  }
  return ''
}

function badges(counts: Counts | undefined): HTMLElement[] {
  if (!counts) return []
  const result: HTMLElement[] = []
  if (counts.errors)
    result.push(el('span', 'badge error', `${counts.errors} ${counts.errors === 1 ? 'error' : 'errors'}`))
  if (counts.warnings) {
    result.push(el('span', 'badge warning', `${counts.warnings} ${counts.warnings === 1 ? 'warning' : 'warnings'}`))
  }
  return result
}

/**
 * The parsed document as an expandable tree, with each finding shown at its element.
 * Branches render when they are first opened, so large trusted lists stay responsive.
 */
export class DocumentTree {
  readonly element: HTMLElement
  private readonly at = new Map<string, PlacedFinding[]>()
  private readonly within = new Map<string, Counts>()
  private readonly nodes = new Map<string, HTMLElement>()
  private readonly renderers = new WeakMap<HTMLElement, () => void>()

  constructor(value: unknown, findings: PlacedFinding[]) {
    for (const finding of findings) {
      const key = pathKey(finding.anchor)
      this.at.set(key, [...(this.at.get(key) ?? []), finding])
      for (let depth = 0; depth <= finding.anchor.length; depth++) {
        const prefix = pathKey(finding.anchor.slice(0, depth))
        const counts = this.within.get(prefix) ?? { errors: 0, warnings: 0 }
        if (finding.severity === 'error') counts.errors++
        else counts.warnings++
        this.within.set(prefix, counts)
      }
    }
    this.element = el('div', 'tree')
    this.element.append(this.node('document', value, []))
  }

  /** Open the tree down to the path, scroll to it and highlight it */
  reveal(path: Path): void {
    for (let depth = 0; depth <= path.length; depth++) {
      const node = this.nodes.get(pathKey(path.slice(0, depth)))
      if (node instanceof HTMLDetailsElement) this.open(node)
    }
    const node = this.nodes.get(pathKey(path))
    const row = node instanceof HTMLDetailsElement ? node.querySelector(':scope > summary') : node?.firstElementChild
    if (!(row instanceof HTMLElement)) return
    row.scrollIntoView({ block: 'center', behavior: 'smooth' })
    row.classList.remove('flash')
    // restart the animation
    void row.offsetWidth
    row.classList.add('flash')
  }

  private open(details: HTMLDetailsElement): void {
    details.open = true
    this.renderers.get(details)?.()
  }

  private node(label: string, value: unknown, path: Path): HTMLElement {
    const key = pathKey(path)
    const own = this.at.get(key) ?? []
    const counts = this.within.get(key)
    let element: HTMLElement

    if (isContainer(value)) {
      const details = el('details', 'node')
      const summary = el('summary', 'row')
      summary.append(el('span', 'key', label), el('span', 'preview', preview(value)), ...badges(counts))
      const children = el('div', 'children')
      details.append(summary, children)

      this.renderers.set(details, () => {
        this.renderers.delete(details)
        children.append(...own.map(findingElement))
        const entries: [string | number, unknown][] = Array.isArray(value)
          ? value.map((item, index) => [index, item])
          : Object.entries(value)
        for (const [childKey, child] of entries) {
          const childPath = [...path, childKey]
          if (typeof child === 'function') continue
          if (child === undefined && !this.within.has(pathKey(childPath))) continue
          children.append(this.node(typeof childKey === 'number' ? `[${childKey}]` : childKey, child, childPath))
        }
        if (entries.length === 0)
          children.append(el('div', 'empty-note', Array.isArray(value) ? 'empty list' : 'empty'))
      })
      details.addEventListener('toggle', () => {
        if (details.open) this.renderers.get(details)?.()
      })
      if (path.length === 0 || counts) this.open(details)
      element = details
    } else {
      const formatted = formatLeaf(value)
      element = el('div', 'leaf')
      const row = el('div', 'row')
      const text = el('span', `value ${formatted.kind}`, formatted.text)
      row.append(el('span', 'key', label), text)
      if (formatted.text.length > MAX_TEXT_SHOWN) {
        text.textContent = `${formatted.text.slice(0, MAX_TEXT_SHOWN)}…`
        const more = el('button', 'more', `show all ${formatted.text.length.toLocaleString()} characters`)
        more.type = 'button'
        more.addEventListener('click', () => {
          text.textContent = formatted.text
          more.remove()
        })
        row.append(more)
      }
      element.append(row, ...own.map(findingElement))
    }

    if (counts) element.classList.add(counts.errors ? 'has-error' : 'has-warning')
    this.nodes.set(key, element)
    return element
  }
}
