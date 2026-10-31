import type { TrustedList } from '@owf/eudi-tl'
import { examples } from '../examples/trusted-list'
import { inspectTrustedListPage } from '../inspectors'
import { startPage } from '../page'
import { el } from '../tree'

/** The lists a list points to, each with a link to inspect it with its signer checked against the LOTL */
function pointers(trustedList: TrustedList): HTMLElement | undefined {
  const entries = trustedList.pointersToOtherLists ?? []
  if (entries.length === 0) return undefined

  const panel = el('div', 'panel')
  panel.append(el('h3', undefined, `Lists it points to (${entries.length})`))
  const table = el('table', 'pointers')
  const head = el('tr')
  head.append(el('th', undefined, 'Territory'), el('th', undefined, 'Type'), el('th', undefined, 'Location'))
  table.append(head)
  for (const pointer of entries) {
    const row = el('tr')
    const link = el('a', undefined, pointer.location)
    link.href = `#${new URLSearchParams({ url: pointer.location, lotl: '1' })}`
    const location = el('td')
    location.append(link)
    row.append(
      el('td', undefined, pointer.schemeTerritory ?? ''),
      el('td', undefined, pointer.tslType?.split('/').pop() ?? ''),
      location
    )
    table.append(row)
  }
  const scroll = el('div', 'table-scroll')
  scroll.append(table)
  panel.append(
    el(
      'p',
      'help',
      'Open a list to inspect it, with its signer checked against the certificates this list has for it. Many servers do not allow other websites to fetch their lists: download those and drop them here.'
    ),
    scroll
  )
  return panel
}

startPage({
  format: 'trusted-list',
  inspect: inspectTrustedListPage,
  extra: (inspection) => pointers(inspection.value as TrustedList),
  examples,
})
