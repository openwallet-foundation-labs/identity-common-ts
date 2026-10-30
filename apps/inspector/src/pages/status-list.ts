import { startPage } from '../page'
import { inspectStatusList } from '../status-list'

startPage({
  format: 'status-list',
  inspect: ({ document, fields }) => inspectStatusList(document, { uri: fields.uri, key: fields.key }),
})
