import { zJsonWebToken } from '../jsonWeb'
import { zEntityStatementClaims } from './entityStatementClaims'
import { zEntityStatementHeader } from './entityStatementHeader'

export const zEntityStatementJwt = zJsonWebToken({
  headerSchema: zEntityStatementHeader,
  claimsSchema: zEntityStatementClaims,
})
