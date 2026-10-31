import { inspectSdJwt } from '@owf/eudi-inspector'
import { startPage } from '../page'

startPage({
  format: 'sd-jwt',
  inspect: ({ document, fields }) => inspectSdJwt(document, { key: fields.key, nonce: fields.nonce, aud: fields.aud }),
})
