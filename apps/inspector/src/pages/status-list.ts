import { examples } from '../examples/status-list'
import { inspectStatusListPage } from '../inspectors'
import { startPage } from '../page'

startPage({ format: 'status-list', inspect: inspectStatusListPage, examples })
