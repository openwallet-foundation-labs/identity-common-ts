import { inspectMdoc } from '../mdoc'
import { startPage } from '../page'

startPage({
  format: 'mdoc',
  inspect: ({ document }) => inspectMdoc(document),
})
