import { IdentityError } from '@owf/identity-common'

/**
 * Base error class for `@openid4vc/utils`, on the shared `IdentityError` base.
 *
 * A value that does not validate is reported with the `ValidationError` of `@owf/identity-common`,
 * which is an `IdentityError` but not an `Openid4vcBaseError`: catch `IdentityError` to
 * handle both.
 */
export abstract class Openid4vcBaseError extends IdentityError {}
