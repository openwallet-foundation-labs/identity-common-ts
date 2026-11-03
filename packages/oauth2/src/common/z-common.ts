import type { FetchHeaders, HttpMethod } from '@openid4vc/utils'

export interface RequestLike {
  headers: FetchHeaders
  method: HttpMethod
  url: string
}
