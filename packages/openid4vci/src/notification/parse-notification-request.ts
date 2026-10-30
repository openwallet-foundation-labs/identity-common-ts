import { Oauth2ErrorCodes, Oauth2ServerErrorResponseError } from '@openid4vc/oauth2'
import { parseWithErrorHandling, ValidationError } from '@openid4vc/utils'
import { type NotificationRequest, zNotificationRequest } from './z-notification'

export interface ParseNotificationRequestOptions {
  /**
   * The JSON body of the notification request
   */
  notificationRequest: unknown
}

export interface ParseNotificationRequestReturn {
  notificationRequest: NotificationRequest
}

/**
 * @throws Oauth2ServerErrorResponseError - with `invalid_notification_request` if the request is invalid
 */
export function parseNotificationRequest(options: ParseNotificationRequestOptions): ParseNotificationRequestReturn {
  try {
    const notificationRequest = parseWithErrorHandling(
      zNotificationRequest,
      options.notificationRequest,
      'Error validating notification request'
    )

    return { notificationRequest }
  } catch (error) {
    throw new Oauth2ServerErrorResponseError(
      {
        error: Oauth2ErrorCodes.InvalidNotificationRequest,
        error_description: error instanceof ValidationError ? error.message : 'Invalid notification request',
      },
      {
        internalMessage: 'Error parsing notification request',
        cause: error,
      }
    )
  }
}
