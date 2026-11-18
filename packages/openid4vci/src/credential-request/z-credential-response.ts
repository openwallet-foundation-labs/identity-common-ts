import { zOauth2ErrorResponse } from '@openid4vc/oauth2'
import { addValidationIssue, zNonEmptyString } from '@owf/identity-common'
import z from 'zod'

const zCredentialEncoding = z.union([z.string(), z.record(z.string(), z.any())])

const zBaseCredentialResponse = z
  .object({
    credentials: z
      .union([
        // Draft >= 15
        z.array(z.object({ credential: zCredentialEncoding })),
        // Draft < 15
        z.array(zCredentialEncoding),
      ])
      .optional(),
    notification_id: zNonEmptyString.optional(),

    transaction_id: zNonEmptyString.optional(),
    interval: z.number().int().positive().optional(),
  })
  .loose()

export const zCredentialResponse = zBaseCredentialResponse
  .extend({
    credential: z.optional(zCredentialEncoding),

    c_nonce: zNonEmptyString.optional(),
    c_nonce_expires_in: z.number().int().optional(),
  })
  .loose()
  .superRefine((value, ctx) => {
    const { credential, credentials, transaction_id, interval, notification_id } = value

    // NOTE: we allow both credential and credentials to be present, to better work with
    // issuers that return both for backwards compatibility
    refineCredentialResponse(ctx, {
      hasCredentials: (credential || credentials) !== undefined,
      transaction_id,
      interval,
      notification_id,
      credentialsName: `'credential'/'credentials'`,
      notificationMessage: `'notification_id' MUST NOT be defined when 'credential' or 'credentials' are not defined.`,
    })
  })

export type CredentialResponse = z.infer<typeof zCredentialResponse>

export const zCredentialErrorResponse = z
  .object({
    ...zOauth2ErrorResponse.shape,

    c_nonce: zNonEmptyString.optional(),
    c_nonce_expires_in: z.number().int().optional(),
  })
  .loose()

export type CredentialErrorResponse = z.infer<typeof zCredentialErrorResponse>

export const zDeferredCredentialResponse = zBaseCredentialResponse.superRefine((value, ctx) => {
  const { credentials, transaction_id, interval, notification_id } = value

  refineCredentialResponse(ctx, {
    hasCredentials: credentials !== undefined,
    transaction_id,
    interval,
    notification_id,
    credentialsName: `'credentials'`,
    notificationMessage: `'notification_id' MUST NOT be defined when 'credentials' is not defined.`,
  })
})

export type DeferredCredentialResponse = z.infer<typeof zDeferredCredentialResponse>

function refineCredentialResponse(
  ctx: z.RefinementCtx,
  options: {
    hasCredentials: boolean
    transaction_id?: string
    interval?: number
    notification_id?: string
    credentialsName: string
    notificationMessage: string
  }
) {
  const { hasCredentials, transaction_id, interval, notification_id, credentialsName } = options
  const exactlyOneMessage = `Exactly one of ${credentialsName}, or 'transaction_id' MUST be defined.`

  if (hasCredentials && transaction_id !== undefined) {
    addValidationIssue(ctx, { code: 'not_allowed', path: ['transaction_id'], message: exactlyOneMessage })
  } else if (!hasCredentials && transaction_id === undefined) {
    addValidationIssue(ctx, {
      code: 'missing_value',
      message: exactlyOneMessage,
      context: { expected: `${credentialsName} or 'transaction_id'` },
    })
  }

  if (transaction_id && !interval) {
    addValidationIssue(ctx, {
      code: 'missing_value',
      path: ['interval'],
      message: `'interval' MUST be defined when 'transaction_id' is defined.`,
      context: { expected: 'number' },
    })
  }

  if (notification_id && !hasCredentials) {
    addValidationIssue(ctx, { code: 'not_allowed', path: ['notification_id'], message: options.notificationMessage })
  }
}
