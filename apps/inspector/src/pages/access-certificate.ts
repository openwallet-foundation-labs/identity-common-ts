import { inspectAccessCertificate } from '@owf/eudi-inspector'
import { startPage } from '../page'

startPage({
  format: 'access-certificate',
  inspect: ({ document, fields }) => inspectAccessCertificate(document, { issuer: fields.issuer }),
})
