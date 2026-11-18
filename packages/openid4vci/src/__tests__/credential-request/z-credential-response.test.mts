import { parseWithSchema } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import { zCredentialResponse } from '../../credential-request/z-credential-response'

describe('Credential Response', () => {
  test('rejects an empty c_nonce', () => {
    expect(
      parseWithSchema(zCredentialResponse, { credentials: [{ credential: 'ey.ey.S' }], c_nonce: '' })
    ).toMatchObject({
      success: false,
      issues: [{ code: 'too_small', path: ['c_nonce'] }],
    })
  })

  // OpenID4VCI 1.0 Section 8.3
  test('gives each violated requirement its code and path', () => {
    expect(parseWithSchema(zCredentialResponse, { transaction_id: 'tx', notification_id: 'n' })).toMatchObject({
      success: false,
      issues: [
        { code: 'missing_value', path: ['interval'], context: { expected: 'number' } },
        { code: 'not_allowed', path: ['notification_id'] },
      ],
    })
    expect(parseWithSchema(zCredentialResponse, {})).toMatchObject({
      success: false,
      issues: [{ code: 'missing_value', path: [] }],
    })
  })
})
