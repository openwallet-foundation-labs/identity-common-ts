import { startPage } from '../page'
import { inspectRegistrationCertificate } from '../registration-certificate'

startPage({
  format: 'registration-certificate',
  inspect: ({ document, fields }) =>
    inspectRegistrationCertificate(document, { accessCertificate: fields.access, key: fields.key }),
})
