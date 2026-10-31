import {
  credential,
  OVER_ASKING_CODES,
  WRP_ENTITLEMENTS,
  WRPRC_VALIDATION_CODES,
  wrprc,
} from '@owf/eudi-registration-certificate'
import { base64urlEncode } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM } from '../../../eudi-access-certificate/src/__tests__/fixtures.mjs'
import { InspectionError } from '../index'
import { checkRequest, parseRequest } from '../over-asking'

const PID_VCT = 'urn:eudi:pid:1'
// The organizationIdentifier of the access certificate fixture
const SUBJECT = 'VATDE-123456789'
const ACCESS_CERTIFICATE = OPENSSL_QCP_L_ACCESS_CERTIFICATE_PEM.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')

const jws = (header: Record<string, unknown>, payload: unknown) =>
  `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(payload))}.c2ln`

const registrationCertificate = (identifier = SUBJECT) =>
  jws(
    { typ: 'rc-wrp+jwt', alg: 'ES256', x5c: [ACCESS_CERTIFICATE], iat: 1_700_000_000 },
    wrprc()
      .name('Example Shop')
      .legalName('Example Shop GmbH')
      .identifier(identifier)
      .country('DE')
      .registryUri('https://registry.test/wrp')
      .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
      .addPurpose('Age verification')
      .addCredential(credential().sdJwtMeta([PID_VCT]).addPathClaim('given_name').build())
      .issuedAt(1_700_000_000)
      .build()
  )

const dcqlQuery = {
  credentials: [
    { id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: [PID_VCT] }, claims: [{ path: ['given_name'] }] },
  ],
}
const overAskingQuery = {
  credentials: [
    {
      id: 'pid',
      format: 'dc+sd-jwt',
      meta: { vct_values: [PID_VCT] },
      claims: [{ path: ['given_name'] }, { path: ['birthdate'] }],
    },
  ],
}

describe('parseRequest', () => {
  it('reads the DCQL query from every form of a request', () => {
    const parameters = { client_id: 'x509_hash:abc', response_type: 'vp_token', dcql_query: dcqlQuery }
    const forms = {
      'DCQL query': JSON.stringify(dcqlQuery),
      'Authorization request': JSON.stringify({ ...parameters, dcql_query: JSON.stringify(dcqlQuery) }),
      'Authorization request URL': `openid4vp://?client_id=x&dcql_query=${encodeURIComponent(JSON.stringify(dcqlQuery))}`,
      'Digital Credentials API request': JSON.stringify({ protocol: 'openid4vp-v1-unsigned', data: parameters }),
      'Request object': jws({ alg: 'ES256', typ: 'oauth-authz-req+jwt' }, parameters),
    }
    for (const [form, input] of Object.entries(forms)) {
      expect(parseRequest(input)).toMatchObject({ form, dcqlQuery })
    }
  })

  it('takes the registration certificate from verifier_info and the access certificate from x5c', () => {
    const request = parseRequest(
      jws(
        { alg: 'ES256', x5c: [ACCESS_CERTIFICATE] },
        {
          dcql_query: dcqlQuery,
          verifier_info: [
            { format: 'jwt', data: jws({ typ: 'JWT' }, {}) },
            { format: 'jwt', data: registrationCertificate() },
          ],
        }
      )
    )
    expect(request.registrationCertificates).toEqual([registrationCertificate()])
    expect(request.accessCertificate).toBe(ACCESS_CERTIFICATE)
  })

  it('asks for the request object of a request by reference', () => {
    expect(() => parseRequest('openid4vp://?client_id=x&request_uri=https%3A%2F%2Fverifier.test%2Fr')).toThrow(
      'request_uri'
    )
  })
})

describe('checkRequest', () => {
  it('accepts a request within the registration', () => {
    const inspection = checkRequest(JSON.stringify({ dcql_query: dcqlQuery }), registrationCertificate())
    expect(inspection.findings.filter((f) => f.severity === 'error')).toEqual([])
    expect(inspection.facts).toContainEqual(['Over-asking', 'None, the request stays within the registration'])
  })

  it('reports over-asking at the claims query of the request', () => {
    const inspection = checkRequest(
      JSON.stringify({
        dcql_query: overAskingQuery,
        verifier_info: [{ format: 'jwt', data: registrationCertificate() }],
      })
    )
    expect(inspection.findings).toContainEqual(
      expect.objectContaining({
        code: OVER_ASKING_CODES.CLAIM_NOT_REGISTERED,
        path: ['dcql_query', 'credentials', 0, 'claims', 1],
      })
    )
    expect(inspection.facts).toContainEqual(['Registration certificate', 'From verifier_info of the request'])
    expect(inspection.facts).toContainEqual(['Over-asking', '1 request goes beyond the registration'])
  })

  it('compares the registration certificate with the access certificate of the request object', () => {
    const requestObject = jws({ alg: 'ES256', x5c: [ACCESS_CERTIFICATE] }, { dcql_query: dcqlQuery })

    const matching = checkRequest(requestObject, registrationCertificate())
    expect(matching.checks).toContain('Subject of the registration certificate against the access certificate')
    expect(matching.findings.map((f) => f.code)).not.toContain(
      WRPRC_VALIDATION_CODES.ACCESS_CERTIFICATE_IDENTITY_MISMATCH
    )

    const other = checkRequest(requestObject, registrationCertificate('VATDE-999999999'))
    expect(other.findings).toContainEqual(
      expect.objectContaining({
        code: WRPRC_VALIDATION_CODES.ACCESS_CERTIFICATE_IDENTITY_MISMATCH,
        path: ['registration_certificate', 'payload', 'sub'],
      })
    )
  })

  it('needs a registration certificate', () => {
    expect(() => checkRequest(JSON.stringify({ dcql_query: dcqlQuery }))).toThrow(InspectionError)
  })
})
