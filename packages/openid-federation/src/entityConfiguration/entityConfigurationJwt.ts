import { zJsonWebToken } from '../jsonWeb'
import { zEntityConfigurationClaims } from './entityConfigurationClaims'
import { zEntityConfigurationHeader } from './entityConfigurationHeader'

export const zEntityConfigurationJwt = zJsonWebToken({
  headerSchema: zEntityConfigurationHeader,
  claimsSchema: zEntityConfigurationClaims,
})
