import { examples } from '../examples/registration-certificate'
import { inspectRegistrationCertificatePage } from '../inspectors'
import { startPage } from '../page'

startPage({ format: 'registration-certificate', inspect: inspectRegistrationCertificatePage, examples })
