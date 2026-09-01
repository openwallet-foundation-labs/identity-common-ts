import {
  type CoseHeadersFor,
  extendCoseHeaderClaims,
  ProtectedHeaders,
  protectedHeadersSchema,
  RegisteredCwtHeaderClaimKey,
} from '@owf/cose'
import z from 'zod'
import { MediaTypes } from '../types'

/**
 * The protected COSE header claims of a status list CWT: the registered ones, with `typ` (16)
 * required and narrowed to the status list media type.
 *
 * `typ` is required in the protected bucket specifically. RFC 9596 puts it there and forbids it in
 * the unprotected headers, so an unprotected `typ` is not integrity protected, and `Cwt.typ` ignores
 * it. The unprotected headers therefore keep the plain `UnprotectedHeaders` structure.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-13.html#name-status-list-token-in-cwt-fo
 * @see https://www.rfc-editor.org/rfc/rfc9596.html#section-2
 */
const statusListCwtProtectedHeaderClaims = extendCoseHeaderClaims([
  [RegisteredCwtHeaderClaimKey.Typ, z.literal(MediaTypes.StatusListCwt)],
] as const)

export class StatusListCwtProtectedHeaders extends ProtectedHeaders<
  CoseHeadersFor<typeof statusListCwtProtectedHeaderClaims>
> {
  public static override get encodingSchema() {
    return protectedHeadersSchema(statusListCwtProtectedHeaderClaims)
  }
}
