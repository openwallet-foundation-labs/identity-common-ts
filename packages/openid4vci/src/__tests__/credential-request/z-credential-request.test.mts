import { parseWithSchema } from '@owf/identity-common'
import { describe, expect, test } from 'vitest'
import {
  zCredentialRequest,
  zCredentialRequestDraft11To14,
  zCredentialRequestDraft14To11,
} from '../../credential-request/z-credential-request'
import { zCredentialRequestCommon } from '../../credential-request/z-credential-request-common'

const compactJwt = 'eyJhbGciOiJFUzI1NiJ9.e30.c2ln'

describe('Credential Request', () => {
  // OpenID4VCI draft 14 Section 7.2: proof and proofs MUST NOT both be present
  test('rejects proof together with proofs as not_allowed at proofs', () => {
    const parseResult = parseWithSchema(zCredentialRequest, {
      format: 'vc+sd-jwt',
      vct: 'some-vct',
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: compactJwt,
      },
      proofs: {
        jwt: [compactJwt],
      },
    })

    expect(parseResult).toMatchObject({
      success: false,
      issues: [
        {
          code: 'invalid_value',
          context: {
            // The draft 11 branch fails on the proofs check alone
            branches: expect.arrayContaining([
              [
                expect.objectContaining({
                  code: 'not_allowed',
                  path: ['proofs'],
                  message: "Both 'proof' and 'proofs' are defined. Only one is allowed",
                }),
              ],
            ]),
          },
        },
      ],
    })
  })

  // OpenID4VCI 1.0 Section 8.2: proofs contains exactly one parameter named as the proof type
  test('rejects proofs without a proof type as too_small at proofs', () => {
    expect(parseWithSchema(zCredentialRequestCommon, { proofs: {} })).toMatchObject({
      success: false,
      issues: [{ code: 'too_small', path: ['proofs'], context: { minimum: 1 } }],
    })
  })

  test('rejects proofs with two proof types as too_big at proofs', () => {
    expect(
      parseWithSchema(zCredentialRequestCommon, { proofs: { jwt: [compactJwt], attestation: [compactJwt] } })
    ).toMatchObject({
      success: false,
      issues: [{ code: 'too_big', path: ['proofs'], context: { maximum: 1 } }],
    })
  })

  // OpenID4VCI 1.0 Section 8.2: the value of the proof type is a non-empty array
  test.each(['jwt', 'attestation', 'some_other_proof_type'])(
    'rejects proofs with an empty %s array as too_small',
    (proofType) => {
      expect(parseWithSchema(zCredentialRequestCommon, { proofs: { [proofType]: [] } })).toMatchObject({
        success: false,
        issues: [{ code: 'too_small', path: ['proofs', proofType], context: { minimum: 1, origin: 'array' } }],
      })
    }
  )

  test('rejects credential_identifier in a draft 11 credential request as not_allowed', () => {
    expect(
      parseWithSchema(zCredentialRequestDraft14To11, {
        format: 'vc+sd-jwt',
        vct: 'some-vct',
        credential_identifier: 'some',
      })
    ).toMatchObject({
      success: false,
      issues: [{ code: 'not_allowed', path: ['credential_identifier'] }],
    })
  })

  test('valid when both format and credential_identifier are defined', () => {
    const parseResult = zCredentialRequest.safeParse({
      format: 'vc+sd-jwt',
      vct: 'some-vct',
      credential_identifier: 'some',
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult.success).toBe(true)
  })

  test('parse draft 14 credential request with vc+sd-jwt format', () => {
    const parseResult = zCredentialRequest.safeParse({
      format: 'vc+sd-jwt',
      vct: 'some-vct',
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      data: {
        format: 'vc+sd-jwt',
        vct: 'some-vct',
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
    })
  })

  test('parse draft 14 credential request with mso_mdoc format', () => {
    const parseResult = zCredentialRequest.safeParse({
      format: 'mso_mdoc',
      doctype: 'eu.pid',
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      data: {
        format: 'mso_mdoc',
        doctype: 'eu.pid',
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
    })
  })

  test('parse draft 14 credential request with ldp_vc format', () => {
    const parseResult = zCredentialRequest.safeParse({
      format: 'ldp_vc',
      credential_definition: {
        '@context': ['context'],
        type: ['types'],
        credentialSubject: {
          claim: {
            mandatory: true,
          },
        },
      },
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      data: {
        format: 'ldp_vc',
        credential_definition: {
          '@context': ['context'],
          type: ['types'],
          credentialSubject: {
            claim: {
              mandatory: true,
            },
          },
        },
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
    })
  })

  test('parse draft 14 credential request with jwt_vc_json-ld format', () => {
    const parseResult = zCredentialRequest.safeParse({
      format: 'jwt_vc_json-ld',
      credential_definition: {
        '@context': ['context'],
        type: ['types'],
        credentialSubject: {
          claim: {
            mandatory: true,
          },
        },
      },
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      data: {
        format: 'jwt_vc_json-ld',
        credential_definition: {
          '@context': ['context'],
          type: ['types'],
          credentialSubject: {
            claim: {
              mandatory: true,
            },
          },
        },
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
    })
  })

  test('parse draft 14 credential request with jwt_vc_json format', () => {
    const parseResult = zCredentialRequest.safeParse({
      format: 'jwt_vc_json',
      credential_definition: {
        type: ['types'],
        credentialSubject: {
          claim: {
            mandatory: true,
          },
        },
      },
      extra_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      data: {
        format: 'jwt_vc_json',
        credential_definition: {
          type: ['types'],
          credentialSubject: {
            claim: {
              mandatory: true,
            },
          },
        },
        extra_prop: 'should-stay',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
    })
  })

  test('parse draft 14 credential request without format with credential_identifier', () => {
    const parseResult = zCredentialRequest.safeParse({
      credential_identifier: 'some-identifier',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      data: {
        credential_identifier: 'some-identifier',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
    })
  })

  test('parse draft 14 credential request without recognized format', () => {
    const parseResult = zCredentialRequest.safeParse({
      format: 'a-new-format',
      some_random_prop: 'should-be-allowed',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      data: {
        format: 'a-new-format',
        some_random_prop: 'should-be-allowed',
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
    })
  })

  test('parse draft 11 credential request with jwt_vc_json format and transfrom to draft 14', () => {
    const parseResult = zCredentialRequestDraft11To14.safeParse({
      format: 'jwt_vc_json',
      types: ['one', 'two'],
      some_other_prop: 'should-stay',
      credentialSubject: {
        some: {
          mandatory: true,
        },
      },
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      data: {
        format: 'jwt_vc_json',
        some_other_prop: 'should-stay',
        credential_definition: {
          type: ['one', 'two'],
          credentialSubject: {
            some: {
              mandatory: true,
            },
          },
        },
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
    })
  })

  test('parse draft 11 credential request with jwt_vc_json-ld format and transfrom to draft 14', () => {
    const parseResult = zCredentialRequest.safeParse({
      format: 'jwt_vc_json-ld',
      credential_definition: {
        '@context': ['context'],
        types: ['one', 'two'],
        credentialSubject: {
          some: {
            mandatory: true,
          },
        },
      },
      some_other_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      data: {
        format: 'jwt_vc_json-ld',
        some_other_prop: 'should-stay',
        credential_definition: {
          '@context': ['context'],
          type: ['one', 'two'],
          credentialSubject: {
            some: {
              mandatory: true,
            },
          },
        },
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
    })
  })

  test('parse draft 11 credential request with ldp_vc format and transfrom to draft 14', () => {
    const parseResult = zCredentialRequest.safeParse({
      format: 'ldp_vc',
      credential_definition: {
        '@context': ['context'],
        types: ['one', 'two'],
        credentialSubject: {
          some: {
            mandatory: true,
          },
        },
      },
      some_other_prop: 'should-stay',
      proof: {
        proof_type: 'jwt',
        jwt: 'ey.ey.S',
      },
    })

    expect(parseResult).toStrictEqual({
      data: {
        format: 'ldp_vc',
        some_other_prop: 'should-stay',
        credential_definition: {
          '@context': ['context'],
          type: ['one', 'two'],
          credentialSubject: {
            some: {
              mandatory: true,
            },
          },
        },
        proof: {
          proof_type: 'jwt',
          jwt: 'ey.ey.S',
        },
      },
      success: true,
    })
  })
})
