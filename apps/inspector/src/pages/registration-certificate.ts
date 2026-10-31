import { inspectRegistrationCertificate } from '@owf/eudi-inspector'
import { startPage } from '../page'

startPage({
  format: 'registration-certificate',
  inspect: ({ document, fields }) =>
    inspectRegistrationCertificate(document, { accessCertificate: fields.access, key: fields.key }),
})
