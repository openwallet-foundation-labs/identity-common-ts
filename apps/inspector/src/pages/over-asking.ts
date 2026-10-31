import { checkRequest } from '@owf/eudi-inspector'
import { startPage } from '../page'

startPage({
  inspect: ({ fields }) => checkRequest(fields.request ?? '', fields.registration ?? ''),
})
