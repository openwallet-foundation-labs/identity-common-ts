import { examples } from '../examples/mdoc'
import { inspectMdocPage } from '../inspectors'
import { startPage } from '../page'

startPage({ format: 'mdoc', inspect: inspectMdocPage, examples })
