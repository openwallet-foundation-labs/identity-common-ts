import { examples } from '../examples/over-asking'
import { checkRequestPage } from '../inspectors'
import { startPage } from '../page'

startPage({ inspect: checkRequestPage, examples })
