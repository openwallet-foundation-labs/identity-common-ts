import type { FetchCallback as IdentityCommonFetchCallback } from '@owf/identity-common'
import type { JsonWebKey } from '../jsonWeb'

export type Optional<T, K extends keyof T> = Pick<Partial<T>, K> & Omit<T, K>

export type SignCallback = (options: { toBeSigned: Uint8Array; jwk: JsonWebKey }) => Promise<Uint8Array>

export type VerifyCallback = (options: {
  jwt: string
  header: Record<string, unknown>
  claims: Record<string, unknown>
  data: Uint8Array
  signature: Uint8Array
  jwk: JsonWebKey
}) => Promise<boolean>

/** What this library fetches. */
export type FederationFetchType = 'entityConfiguration' | 'entityStatement'

/**
 * Fetches an entity configuration or an entity statement. It gets `{ type: 'entityConfiguration' }` or
 * `{ type: 'entityStatement' }` as its third argument, and the global `fetch` satisfies it.
 */
export type FetchCallback = IdentityCommonFetchCallback<FederationFetchType>
