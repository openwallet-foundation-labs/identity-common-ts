import { inspectLoTE } from '../lote'
import { startPage } from '../page'

startPage({
  format: 'lote',
  inspect: ({ document, fields }) => inspectLoTE(document, { key: fields.key }),
})
