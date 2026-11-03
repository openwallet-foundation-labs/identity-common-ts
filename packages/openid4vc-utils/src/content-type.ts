import { isMediaType } from '@owf/identity-common'
import type { FetchResponse } from './globals'

export enum ContentType {
  XWwwFormUrlencoded = 'application/x-www-form-urlencoded',
  Json = 'application/json',
  JwkSet = 'application/jwk-set+json',
  OauthAuthorizationRequestJwt = 'application/oauth-authz-req+jwt',
  Jwt = 'application/jwt',
  Html = 'text/html',
}

/** Whether `value` has the media type `contentType`, ignoring casing and parameters */
export function isContentType(contentType: ContentType, value: string) {
  return isMediaType(value, contentType)
}

export function isResponseContentType(contentType: ContentType | ContentType[], response: FetchResponse) {
  const contentTypeArray = Array.isArray(contentType) ? contentType : [contentType]

  return isMediaType(response.headers.get('Content-Type'), contentTypeArray)
}
