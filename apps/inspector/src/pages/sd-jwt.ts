import { examples } from '../examples/sd-jwt'
import { inspectSdJwtPage } from '../inspectors'
import { startPage } from '../page'

startPage({ format: 'sd-jwt', inspect: inspectSdJwtPage, examples })
