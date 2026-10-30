import { checkRequest } from '../over-asking'
import { startPage } from '../page'

startPage({
  inspect: ({ fields }) => checkRequest(fields.request ?? '', fields.registration ?? ''),
})
