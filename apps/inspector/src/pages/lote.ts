import { inspectLoTE } from '@owf/eudi-inspector'
import { startPage } from '../page'

startPage({
  format: 'lote',
  inspect: ({ document, fields }) => inspectLoTE(document, { key: fields.key }),
})
