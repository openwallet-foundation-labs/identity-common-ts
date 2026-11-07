import { decodeJwt, JoseValidationError, signJwt } from '@owf/jose'
import { describe, expect, it } from 'vitest'
import { zReferencedTokenJwtPayload } from '../jwt-types'
import { jwsSigner, signJws } from './context'
import { uri } from './status-list-jwt-tokens'

const referencedToken = async (status: unknown) =>
  (
    await signJwt({
      payload: { iss: 'https://example.com', sub: 'user123', status },
      signer: jwsSigner,
      signJwsCallback: signJws,
    })
  ).jwt

const decodeReferencedToken = (jwt: string) => decodeJwt({ jwt, payloadSchema: zReferencedTokenJwtPayload })

describe('zReferencedTokenJwtPayload', () => {
  it('reads the idx and uri of the status list entry', async () => {
    const { payload } = decodeReferencedToken(await referencedToken({ status_list: { idx: 42, uri } }))

    expect(payload.status.status_list).toEqual({ idx: 42, uri })
  })

  it('keeps the other members of the status claim', async () => {
    const { payload } = decodeReferencedToken(
      await referencedToken({ status_list: { idx: 0, uri }, other_mechanism: { id: 7 } })
    )

    expect(payload.status).toEqual({ status_list: { idx: 0, uri }, other_mechanism: { id: 7 } })
  })

  it('rejects a token whose status claim has no status list entry', async () => {
    const jwt = await referencedToken({ other_mechanism: { id: 7 } })

    expect(() => decodeReferencedToken(jwt)).toThrow(JoseValidationError)
    expect(() => decodeReferencedToken(jwt)).toThrow('- status.status_list: ')
  })

  it.each([
    ['negative', -1],
    ['fractional', 1.5],
    ['string', '42'],
  ])('rejects a %s idx', async (_name, idx) => {
    const jwt = await referencedToken({ status_list: { idx, uri } })

    expect(() => decodeReferencedToken(jwt)).toThrow(JoseValidationError)
    expect(() => decodeReferencedToken(jwt)).toThrow('- status.status_list.idx: ')
  })

  it('rejects a status list entry without a uri', async () => {
    const jwt = await referencedToken({ status_list: { idx: 42 } })

    expect(() => decodeReferencedToken(jwt)).toThrow(JoseValidationError)
    expect(() => decodeReferencedToken(jwt)).toThrow('- status.status_list.uri: ')
  })
})
