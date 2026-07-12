/**
 *
 * Registered CWT claim keys
 * @see https://www.rfc-editor.org/rfc/rfc8392#section-3.1
 *
 */
export enum RegisteredCwtClaimKey {
  Issuer = 1,
  Subject = 2,
  Audience = 3,
  ExpirationTime = 4,
  NotBefore = 5,
  IssuedAt = 6,
  CwtId = 7,
}
