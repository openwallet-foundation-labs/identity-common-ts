import { examples } from '../examples/lote'
import { inspectLoTEPage } from '../inspectors'
import { startPage } from '../page'

startPage({ format: 'lote', inspect: inspectLoTEPage, examples })
