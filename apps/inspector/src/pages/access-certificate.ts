import { inspectAccessCertificate } from '../access-certificate'
import { startPage } from '../page'

startPage({
  format: 'access-certificate',
  inspect: ({ document, fields }) => inspectAccessCertificate(document, { issuer: fields.issuer }),
})
