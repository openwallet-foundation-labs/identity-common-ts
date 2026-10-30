import { startPage } from '../page'
import { inspectSdJwt } from '../sd-jwt'

startPage({
  format: 'sd-jwt',
  inspect: ({ document, fields }) => inspectSdJwt(document, { key: fields.key, nonce: fields.nonce, aud: fields.aud }),
})
