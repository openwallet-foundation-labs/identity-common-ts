import { examples } from '../examples/access-certificate'
import { inspectAccessCertificatePage } from '../inspectors'
import { startPage } from '../page'

startPage({ format: 'access-certificate', inspect: inspectAccessCertificatePage, examples })
