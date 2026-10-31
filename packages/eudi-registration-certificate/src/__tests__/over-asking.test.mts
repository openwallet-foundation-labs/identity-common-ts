import { DcqlQuery } from 'dcql'
import { describe, expect, it } from 'vitest'
import { OVER_ASKING_CODES as CODES, checkOverAsking, credential } from '../index'

const PID_VCT = 'urn:eudi:pid:1'
const PID_DOCTYPE = 'eu.europa.ec.eudi.pid.1'

const registered = [
  credential()
    .sdJwtMeta([PID_VCT])
    .addPathClaim('given_name')
    .addPathClaim('family_name')
    .addPathClaim('address')
    .addPathClaim('nationalities', null)
    .addClaim({ path: ['age_equal_or_over', '18'], values: [true] })
    .build(),
  credential().mdocMeta(PID_DOCTYPE).addPathClaim(PID_DOCTYPE, 'family_name').build(),
]

const sdJwtQuery = (claims: unknown[], meta: Record<string, unknown> = { vct_values: [PID_VCT] }) => ({
  credentials: [{ id: 'pid', format: 'dc+sd-jwt', meta, claims }],
})

const codesAndPaths = (result: ReturnType<typeof checkOverAsking>) =>
  result.findings.map(({ severity, code, path }) => ({ severity, code, path }))

describe('checkOverAsking', () => {
  it('accepts registered claims and members of registered objects', () => {
    const result = checkOverAsking(
      sdJwtQuery([{ path: ['given_name'] }, { path: ['address', 'locality'] }, { path: ['nationalities', 0] }]),
      registered
    )
    expect(result).toEqual({ valid: true, findings: [] })
  })

  it('reports a claim that is not registered, at the claims query', () => {
    const result = checkOverAsking(sdJwtQuery([{ path: ['given_name'] }, { path: ['birthdate'] }]), registered)
    expect(result.valid).toBe(false)
    expect(result.findings).toEqual([
      {
        severity: 'error',
        code: CODES.CLAIM_NOT_REGISTERED,
        path: ['credentials', 0, 'claims', 1],
        message: 'Credential query pid asks for the claim ["birthdate"], which is not registered',
      },
    ])
  })

  it('does not let a registered member cover its parent, nor an index cover every element', () => {
    const narrow = [credential().sdJwtMeta([PID_VCT]).addPathClaim('address', 'locality').addPathClaim('x', 0).build()]
    const result = checkOverAsking(sdJwtQuery([{ path: ['address'] }, { path: ['x', null] }]), narrow)
    expect(codesAndPaths(result)).toEqual([
      { severity: 'error', code: CODES.CLAIM_NOT_REGISTERED, path: ['credentials', 0, 'claims', 0] },
      { severity: 'error', code: CODES.CLAIM_NOT_REGISTERED, path: ['credentials', 0, 'claims', 1] },
    ])
  })

  it('only allows the registered values of a claim', () => {
    const ageClaim = (values?: unknown[]) => ({ path: ['age_equal_or_over', '18'], ...(values ? { values } : {}) })

    expect(checkOverAsking(sdJwtQuery([ageClaim([true])]), registered).valid).toBe(true)
    expect(codesAndPaths(checkOverAsking(sdJwtQuery([ageClaim(), ageClaim([false])]), registered))).toEqual([
      { severity: 'error', code: CODES.CLAIM_VALUES_NOT_REGISTERED, path: ['credentials', 0, 'claims', 0, 'values'] },
      { severity: 'error', code: CODES.CLAIM_VALUES_NOT_REGISTERED, path: ['credentials', 0, 'claims', 1, 'values'] },
    ])
  })

  it('reports a credential whose format or meta is not registered', () => {
    const query = {
      credentials: [
        { id: 'other_vct', format: 'dc+sd-jwt', meta: { vct_values: [PID_VCT, 'urn:example:other'] } },
        { id: 'any_vct', format: 'dc+sd-jwt', meta: {} },
        { id: 'w3c', format: 'jwt_vc_json', meta: { type_values: [['VerifiableCredential']] } },
      ],
    }
    expect(codesAndPaths(checkOverAsking(query, registered))).toEqual([
      { severity: 'error', code: CODES.CREDENTIAL_NOT_REGISTERED, path: ['credentials', 0, 'meta'] },
      { severity: 'error', code: CODES.CREDENTIAL_NOT_REGISTERED, path: ['credentials', 1, 'meta'] },
      { severity: 'error', code: CODES.CREDENTIAL_NOT_REGISTERED, path: ['credentials', 2, 'format'] },
    ])
  })

  it('checks only the credential of a query without claims', () => {
    expect(
      checkOverAsking({ credentials: [{ format: 'dc+sd-jwt', meta: { vct_values: [PID_VCT] } }] }, registered)
    ).toEqual({ valid: true, findings: [] })
  })

  it('reads mdoc claims in either form, and a parsed DcqlQuery', () => {
    const query = DcqlQuery.parse({
      credentials: [
        {
          id: 'mdl',
          format: 'mso_mdoc',
          meta: { doctype_value: PID_DOCTYPE },
          claims: [
            { path: [PID_DOCTYPE, 'family_name'], intent_to_retain: false },
            { namespace: PID_DOCTYPE, claim_name: 'family_name' },
            { path: [PID_DOCTYPE, 'portrait'], intent_to_retain: false },
          ],
        },
      ],
    })
    expect(codesAndPaths(checkOverAsking(query, registered))).toEqual([
      { severity: 'error', code: CODES.CLAIM_NOT_REGISTERED, path: ['credentials', 0, 'claims', 2] },
    ])
  })

  it('warns when the registered credential lists no claims', () => {
    const withoutClaims = [credential().sdJwtMeta([PID_VCT]).build()]
    const result = checkOverAsking(sdJwtQuery([{ path: ['given_name'] }]), withoutClaims)
    expect(result.valid).toBe(true)
    expect(codesAndPaths(result)).toEqual([
      { severity: 'warning', code: CODES.CLAIMS_NOT_LISTED, path: ['credentials', 0, 'claims'] },
    ])
  })

  it('reads the claims spelling of the registered credentials', () => {
    const spelledClaims = [{ format: 'dc+sd-jwt', meta: { vct_values: [PID_VCT] }, claims: [{ path: ['given_name'] }] }]
    expect(checkOverAsking(sdJwtQuery([{ path: ['given_name'] }]), spelledClaims).valid).toBe(true)
  })

  it('reports a query that is not a DCQL query', () => {
    expect(codesAndPaths(checkOverAsking({ credential: [] }, registered))).toEqual([
      { severity: 'error', code: CODES.INVALID_QUERY, path: ['credentials'] },
    ])
    expect(codesAndPaths(checkOverAsking(sdJwtQuery([{ id: 'no_path' }]), registered))).toEqual([
      { severity: 'error', code: CODES.INVALID_QUERY, path: ['credentials', 0, 'claims', 0] },
    ])
  })

  it('reports every credential as not registered without a registration', () => {
    expect(codesAndPaths(checkOverAsking(sdJwtQuery([{ path: ['given_name'] }]), []))).toEqual([
      { severity: 'error', code: CODES.CREDENTIAL_NOT_REGISTERED, path: ['credentials', 0, 'format'] },
    ])
  })
})
