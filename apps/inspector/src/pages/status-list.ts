import { inspectStatusList } from '@owf/eudi-inspector'
import { startPage } from '../page'

startPage({
  format: 'status-list',
  inspect: ({ document, fields }) => inspectStatusList(document, { uri: fields.uri, key: fields.key }),
})
