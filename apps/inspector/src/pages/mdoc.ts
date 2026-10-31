import { inspectMdoc } from '@owf/eudi-inspector'
import { startPage } from '../page'

startPage({
  format: 'mdoc',
  inspect: ({ document }) => inspectMdoc(document),
})
