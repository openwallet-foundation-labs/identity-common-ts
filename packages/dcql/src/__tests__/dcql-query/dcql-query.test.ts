import assert from 'node:assert'
import { IdentityError } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { DcqlParseError } from '../../dcql-error/e-dcql.js'
import { DcqlPresentationResult } from '../../dcql-presentation/m-dcql-presentation-result.js'
import { DcqlQuery } from '../../dcql-query/m-dcql-query.js'
import type { DcqlMdocCredential, DcqlSdJwtVcCredential, DcqlW3cVcCredential } from '../../u-dcql-credential.js'

/**
 * The following is a non-normative example of a DCQL query that requests
 * a Verifiable Credential in the format mso_mdoc with the claims vehicle_holder and first_name:
 */
const mdocMvrcQuery = {
  credentials: [
    {
      id: 'my_credential',
      format: 'mso_mdoc' as const,
      meta: { doctype_value: 'org.iso.7367.1.mVRC' },
      require_cryptographic_holder_binding: true,
      claims: [
        { path: ['org.iso.7367.1', 'vehicle_holder'], intent_to_retain: false },
        { path: ['org.iso.18013.5.1', 'first_name'], intent_to_retain: true },
      ],
      trusted_authorities: [
        {
          type: 'aki',
          values: ['one', 'two'],
        },
        {
          type: 'openid_federation',
          values: ['https://federation.com', 'https://agent.com'],
        },
      ],
    },
  ],
} satisfies DcqlQuery.Input

/**
 * The following is a non-normative example of a DCQL query that requests
 * a Verifiable Credential in the format mso_mdoc with the claims vehicle_holder and first_name
 * in the old syntax, leveraging `namespace` and `claim_name`
 */
const mdocNamespaceMvrcQuery = {
  credentials: [
    {
      id: 'my_credential',
      format: 'mso_mdoc' as const,
      meta: { doctype_value: 'org.iso.7367.1.mVRC' },
      claims: [
        { namespace: 'org.iso.7367.1', claim_name: 'vehicle_holder' },
        { namespace: 'org.iso.18013.5.1', claim_name: 'first_name' },
      ],
      require_cryptographic_holder_binding: false,
    },
  ],
} satisfies DcqlQuery.Input

const mdocMvrc = {
  credential_format: 'mso_mdoc',
  doctype: 'org.iso.7367.1.mVRC',
  namespaces: {
    'org.iso.7367.1': {
      vehicle_holder: 'Martin Auer',
      non_disclosed: 'secret',
    },
    'org.iso.18013.5.1': { first_name: 'Martin Auer' },
  },
  authority: {
    type: 'aki',
    values: ['one'],
  },
  cryptographic_holder_binding: true,
} satisfies DcqlMdocCredential

const exampleMdoc = {
  credential_format: 'mso_mdoc',
  doctype: 'example_doctype',
  namespaces: {
    example_namespaces: {
      example_claim: 'example_value',
    },
  },
  authority: {
    type: 'aki',
    values: ['something'],
  },
  cryptographic_holder_binding: true,
} satisfies DcqlMdocCredential

const sdJwtDcExampleQuery = {
  credentials: [
    {
      id: 'my_credential',
      format: 'dc+sd-jwt',
      meta: {
        vct_values: ['https://credentials.example.com/identity_credential'],
      },
      claims: [{ path: ['last_name'] }, { path: ['first_name'] }, { path: ['address', 'street_address'] }],
      require_cryptographic_holder_binding: false,
    },
  ],
} satisfies DcqlQuery.Input

const sdJwtDcMultipleExampleQuery = {
  credentials: [
    {
      id: 'my_credential',
      format: 'dc+sd-jwt',
      multiple: true,
      meta: {
        vct_values: ['https://credentials.example.com/identity_credential'],
      },
      claims: [{ path: ['last_name'] }, { path: ['first_name'] }, { path: ['address', 'street_address'] }],
      require_cryptographic_holder_binding: false,
    },
  ],
} satisfies DcqlQuery.Input

const exampleSdJwtDc = {
  credential_format: 'dc+sd-jwt',
  vct: 'https://credentials.example.com/identity_credential',
  claims: {
    first_name: 'Arthur',
    last_name: 'Dent',
    address: {
      street_address: '42 Market Street',
      locality: 'Milliways',
      postal_code: '12345',
    },
    degrees: [
      {
        type: 'Bachelor of Science',
        university: 'University of Betelgeuse',
      },
      {
        type: 'Master of Science',
        university: 'University of Betelgeuse',
      },
    ],
    nationalities: ['British', 'Betelgeusian'],
  },
  cryptographic_holder_binding: false,
} satisfies DcqlSdJwtVcCredential

const legacySdJwtVcExampleQuery = {
  credentials: [
    {
      id: 'my_credential',
      format: 'vc+sd-jwt',
      meta: {
        vct_values: ['https://credentials.example.com/identity_credential'],
      },
      claims: [{ path: ['last_name'] }, { path: ['first_name'] }, { path: ['address', 'street_address'] }],
      require_cryptographic_holder_binding: false,
    },
  ],
} satisfies DcqlQuery.Input

const legacySdJwtDcMultipleExampleQuery = {
  credentials: [
    {
      id: 'my_credential',
      format: 'vc+sd-jwt',
      multiple: true,
      meta: {
        vct_values: ['https://credentials.example.com/identity_credential'],
      },
      claims: [{ path: ['last_name'] }, { path: ['first_name'] }, { path: ['address', 'street_address'] }],
      require_cryptographic_holder_binding: false,
    },
  ],
} satisfies DcqlQuery.Input

const exampleLegacySdJwtVc = {
  credential_format: 'vc+sd-jwt',
  vct: 'https://credentials.example.com/identity_credential',
  claims: {
    first_name: 'Arthur',
    last_name: 'Dent',
    address: {
      street_address: '42 Market Street',
      locality: 'Milliways',
      postal_code: '12345',
    },
    degrees: [
      {
        type: 'Bachelor of Science',
        university: 'University of Betelgeuse',
      },
      {
        type: 'Master of Science',
        university: 'University of Betelgeuse',
      },
    ],
    nationalities: ['British', 'Betelgeusian'],
  },
  cryptographic_holder_binding: false,
} satisfies DcqlSdJwtVcCredential

/**
 * The following is a non-normative example of a DCQL query that requests
 * a Verifiable Credential in the format mso_mdoc with the claims vehicle_holder and first_name:
 */
const w3cLdpVcQuery = {
  credentials: [
    {
      id: 'my_credential',
      format: 'ldp_vc',
      meta: {
        type_values: [
          ['https://example.org/examples#AlumniCredential', 'https://example.org/examples#BachelorDegree'],
          [
            'https://www.w3.org/2018/credentials#VerifiableCredential',
            'https://example.org/examples#UniversityDegreeCredential',
          ],
        ],
      },
      claims: [
        {
          path: ['last_name'],
        },
        { path: ['first_name'] },
        { path: ['address', 'street_address'] },
      ],
      require_cryptographic_holder_binding: false,
    },
  ],
} satisfies DcqlQuery.Input

const exampleW3cLdpVc = {
  credential_format: 'ldp_vc',
  type: [
    'https://www.w3.org/2018/credentials#VerifiableCredential',
    'https://example.org/examples#AlumniCredential',
    'https://example.org/examples#BachelorDegree',
  ],
  claims: {
    first_name: 'Arthur',
    last_name: 'Dent',
    address: {
      street_address: '42 Market Street',
      locality: 'Milliways',
      postal_code: '12345',
    },
    degrees: [
      {
        type: 'Bachelor of Science',
        university: 'University of Betelgeuse',
      },
      {
        type: 'Master of Science',
        university: 'University of Betelgeuse',
      },
    ],
    nationalities: ['British', 'Betelgeusian'],
  },
  cryptographic_holder_binding: false,
} satisfies DcqlW3cVcCredential

const sdJwtVcQuery = {
  credentials: [
    {
      id: 'my_credential',
      format: 'vc+sd-jwt',
      meta: {
        type_values: [
          ['https://example.org/examples#AlumniCredential', 'https://example.org/examples#BachelorDegree'],
          ['https://www.w3.org/ns/credentials/v2', 'https://example.org/examples#UniversityDegreeCredential'],
        ],
      },
      claims: [
        {
          path: ['last_name'],
        },
        { path: ['first_name'] },
        { path: ['address', 'street_address'] },
      ],
    },
  ],
} satisfies DcqlQuery.Input

const exampleSdJwtVc = {
  credential_format: 'vc+sd-jwt',
  type: [
    'https://www.w3.org/ns/credentials/v2',
    'https://example.org/examples#AlumniCredential',
    'https://example.org/examples#BachelorDegree',
  ],
  claims: {
    first_name: 'Arthur',
    last_name: 'Dent',
    address: {
      street_address: '42 Market Street',
      locality: 'Milliways',
      postal_code: '12345',
    },
    degrees: [
      {
        type: 'Bachelor of Science',
        university: 'University of Betelgeuse',
      },
      {
        type: 'Master of Science',
        university: 'University of Betelgeuse',
      },
    ],
    nationalities: ['British', 'Betelgeusian'],
  },
  cryptographic_holder_binding: true,
} satisfies DcqlW3cVcCredential

describe('dcql-query', () => {
  it('rejects a meta that is an array', () => {
    for (const format of ['mso_mdoc', 'dc+sd-jwt'] as const) {
      expect(() => DcqlQuery.parse({ credentials: [{ id: 'credential', format, meta: [] as never }] })).toThrow(
        expect.objectContaining({
          issues: [expect.objectContaining({ code: 'invalid_type', path: ['credentials', 0, 'meta'] })],
        })
      )
    }
  })

  it('mdoc mvrc query fails with invalid mdoc', (_t) => {
    const query = DcqlQuery.parse(mdocMvrcQuery)
    DcqlQuery.validate(query)

    const credentials = [exampleMdoc]
    const res = DcqlQuery.query(query, credentials)

    assert(!res.can_be_satisfied)
    assert.deepStrictEqual(res.credential_matches, {
      my_credential: {
        success: false,
        credential_query_id: 'my_credential',
        failed_credentials: [
          {
            success: false,
            input_credential_index: 0,
            trusted_authorities: {
              failed_trusted_authorities: [
                {
                  issues: [
                    {
                      severity: 'error',
                      code: 'trusted_authority_mismatch',
                      path: ['values'],
                      message:
                        "Expected one of the trusted authority values to be 'one' | 'two' but received 'something'",
                      context: {
                        actual: { type: 'aki', values: ['something'] },
                        expected: { type: 'aki', values: ['one', 'two'] },
                      },
                    },
                  ],
                  success: false,
                  trusted_authority_index: 0,
                },
                {
                  issues: [
                    {
                      severity: 'error',
                      code: 'trusted_authority_mismatch',
                      path: ['type'],
                      message: "Expected trusted authority type to be 'openid_federation' but received 'aki'",
                      context: {
                        actual: { type: 'aki', values: ['something'] },
                        expected: {
                          type: 'openid_federation',
                          values: ['https://federation.com', 'https://agent.com'],
                        },
                      },
                    },
                    {
                      severity: 'error',
                      code: 'trusted_authority_mismatch',
                      path: ['values'],
                      message:
                        "Expected one of the trusted authority values to be 'https://federation.com' | 'https://agent.com' but received 'something'",
                      context: {
                        actual: { type: 'aki', values: ['something'] },
                        expected: {
                          type: 'openid_federation',
                          values: ['https://federation.com', 'https://agent.com'],
                        },
                      },
                    },
                  ],
                  success: false,
                  trusted_authority_index: 1,
                },
              ],
              success: false,
            },
            meta: {
              success: false,
              issues: [
                {
                  severity: 'error',
                  code: 'doctype_mismatch',
                  path: ['doctype'],
                  message: "Expected doctype to be 'org.iso.7367.1.mVRC' but received 'example_doctype'",
                  context: { actual: 'example_doctype', expected: 'org.iso.7367.1.mVRC' },
                },
              ],
            },
            claims: {
              success: false,
              failed_claim_sets: [
                {
                  claim_set_index: undefined,
                  success: false,
                  failed_claim_indexes: [0, 1],
                  valid_claim_indexes: undefined,
                  issues: [
                    {
                      severity: 'error',
                      code: 'claim_missing',
                      path: ['org.iso.7367.1'],
                      message: "Expected claim 'org.iso.7367.1'.'vehicle_holder' to be defined",
                    },
                    {
                      severity: 'error',
                      code: 'claim_missing',
                      path: ['org.iso.18013.5.1'],
                      message: "Expected claim 'org.iso.18013.5.1'.'first_name' to be defined",
                    },
                  ],
                },
              ],
              failed_claims: [
                {
                  success: false,
                  claim_id: undefined,
                  issues: [
                    {
                      severity: 'error',
                      code: 'claim_missing',
                      path: ['org.iso.7367.1'],
                      message: "Expected claim 'org.iso.7367.1'.'vehicle_holder' to be defined",
                    },
                  ],
                  claim_index: 0,
                },
                {
                  success: false,
                  claim_id: undefined,
                  issues: [
                    {
                      severity: 'error',
                      code: 'claim_missing',
                      path: ['org.iso.18013.5.1'],
                      message: "Expected claim 'org.iso.18013.5.1'.'first_name' to be defined",
                    },
                  ],
                  claim_index: 1,
                },
              ],
              valid_claims: undefined,
            },
          },
        ],
        valid_credentials: undefined,
      },
    })
  })

  it('mdoc mvrc example with multiple credentials succeeds', (_t) => {
    const query = DcqlQuery.parse(mdocMvrcQuery)
    DcqlQuery.validate(query)

    const res = DcqlQuery.query(query, [exampleMdoc, mdocMvrc])

    assert(res.can_be_satisfied)
    assert.deepStrictEqual(res.credential_matches, {
      my_credential: {
        success: true,
        credential_query_id: 'my_credential',
        failed_credentials: res.credential_matches.my_credential.failed_credentials,
        valid_credentials: [
          {
            claims: {
              failed_claim_sets: undefined,
              failed_claims: undefined,
              success: true,
              valid_claim_sets: [
                {
                  claim_set_index: undefined,
                  output: {
                    'org.iso.18013.5.1': {
                      first_name: 'Martin Auer',
                    },
                    'org.iso.7367.1': {
                      vehicle_holder: 'Martin Auer',
                    },
                  },
                  success: true,
                  valid_claim_indexes: [0, 1],
                },
              ],
              valid_claims: [
                {
                  claim_id: undefined,
                  claim_index: 0,
                  output: {
                    'org.iso.7367.1': {
                      vehicle_holder: 'Martin Auer',
                    },
                  },
                  success: true,
                },
                {
                  claim_id: undefined,
                  claim_index: 1,
                  output: {
                    'org.iso.18013.5.1': {
                      first_name: 'Martin Auer',
                    },
                  },
                  success: true,
                },
              ],
            },
            input_credential_index: 1,
            meta: {
              output: {
                credential_format: 'mso_mdoc',
                doctype: 'org.iso.7367.1.mVRC',
                cryptographic_holder_binding: true,
              },
              success: true,
            },
            success: true,
            trusted_authorities: {
              failed_trusted_authorities: undefined,
              success: true,
              valid_trusted_authority: {
                output: {
                  type: 'aki',
                  value: 'one',
                },
                success: true,
                trusted_authority_index: 0,
              },
            },
          },
        ],
      },
    } as const)

    const validCredential = res.credential_matches.my_credential.valid_credentials[0]
    const presentationQueryResult = DcqlPresentationResult.fromDcqlPresentation(
      {
        my_credential: [
          {
            ...validCredential.meta.output,
            authority: {
              ...validCredential.trusted_authorities.valid_trusted_authority?.output,
              values: [validCredential.trusted_authorities.valid_trusted_authority?.output.value],
            },
            namespaces: validCredential.claims.valid_claim_sets[0].output,
          },
        ],
      },
      { dcqlQuery: query }
    )

    assert(presentationQueryResult.can_be_satisfied)
    assert.deepStrictEqual(presentationQueryResult.credential_matches, {
      my_credential: {
        success: true,
        credential_query_id: 'my_credential',
        failed_credentials: undefined,
        valid_credentials: [
          {
            success: true,
            input_credential_index: 0,
            trusted_authorities: {
              success: true,
              valid_trusted_authority: {
                success: true,
                trusted_authority_index: 0,
                output: {
                  type: 'aki',
                  value: 'one',
                },
              },
              failed_trusted_authorities: undefined,
            },
            meta: {
              success: true,
              output: {
                credential_format: 'mso_mdoc',
                doctype: 'org.iso.7367.1.mVRC',
                cryptographic_holder_binding: true,
              },
            },
            claims: {
              success: true,
              failed_claim_sets: undefined,
              valid_claim_sets: [
                {
                  success: true,
                  claim_set_index: undefined,
                  output: {
                    'org.iso.7367.1': {
                      vehicle_holder: 'Martin Auer',
                    },
                    'org.iso.18013.5.1': {
                      first_name: 'Martin Auer',
                    },
                  },
                  valid_claim_indexes: [0, 1],
                },
              ],
              valid_claims: [
                {
                  success: true,
                  claim_id: undefined,
                  claim_index: 0,
                  output: {
                    'org.iso.7367.1': {
                      vehicle_holder: 'Martin Auer',
                    },
                  },
                },
                {
                  success: true,
                  claim_index: 1,
                  claim_id: undefined,
                  output: {
                    'org.iso.18013.5.1': {
                      first_name: 'Martin Auer',
                    },
                  },
                },
              ],
              failed_claims: undefined,
            },
          },
        ],
      },
    })
  })

  it('w3cLdpVc example succeeds', (_t) => {
    const query = DcqlQuery.parse(w3cLdpVcQuery)
    DcqlQuery.validate(query)

    const credentials = [exampleW3cLdpVc]
    const res = DcqlQuery.query(query, credentials)

    assert(res.can_be_satisfied)
    assert.deepStrictEqual(res.credential_matches, {
      my_credential: {
        success: true,
        credential_query_id: 'my_credential',
        failed_credentials: undefined,
        valid_credentials: [
          {
            success: true,
            input_credential_index: 0,
            trusted_authorities: {
              success: true,
            },
            meta: {
              success: true,
              output: {
                credential_format: 'ldp_vc',
                cryptographic_holder_binding: false,
                type: [
                  'https://www.w3.org/2018/credentials#VerifiableCredential',
                  'https://example.org/examples#AlumniCredential',
                  'https://example.org/examples#BachelorDegree',
                ],
              },
            },
            claims: {
              success: true,
              failed_claim_sets: undefined,
              valid_claim_sets: [
                {
                  success: true,
                  claim_set_index: undefined,
                  output: {
                    last_name: 'Dent',
                    first_name: 'Arthur',
                    address: {
                      street_address: '42 Market Street',
                    },
                  },
                  valid_claim_indexes: [0, 1, 2],
                },
              ],
              valid_claims: [
                {
                  success: true,
                  claim_id: undefined,
                  claim_index: 0,
                  output: {
                    last_name: 'Dent',
                  },
                },
                {
                  success: true,
                  claim_id: undefined,
                  claim_index: 1,
                  output: {
                    first_name: 'Arthur',
                  },
                },
                {
                  success: true,
                  claim_id: undefined,
                  claim_index: 2,
                  output: {
                    address: {
                      street_address: '42 Market Street',
                    },
                  },
                },
              ],
              failed_claims: undefined,
            },
          },
        ],
      },
    })
  })

  it('w3cLdpVc query fails with invalid type values', (_t) => {
    const query = DcqlQuery.parse(w3cLdpVcQuery)
    DcqlQuery.validate(query)

    const credentials = [
      {
        ...exampleW3cLdpVc,
        // Override type
        type: [
          'https://www.w3.org/2018/credentials#VerifiableCredential',
          'https://example.org/examples#AlumniCredential',
        ],
      },
    ]
    const res = DcqlQuery.query(query, credentials)

    assert(!res.can_be_satisfied)
    expect(res.credential_matches).toStrictEqual({
      my_credential: {
        success: false,
        credential_query_id: 'my_credential',
        valid_credentials: undefined,
        failed_credentials: [
          {
            success: false,
            input_credential_index: 0,
            trusted_authorities: {
              success: true,
            },
            meta: {
              success: false,
              issues: [
                {
                  severity: 'error',
                  code: 'type_mismatch',
                  path: ['type'],
                  message:
                    'Expected type to include all values from one of the following subsets: [https://example.org/examples#AlumniCredential, https://example.org/examples#BachelorDegree] | [https://www.w3.org/2018/credentials#VerifiableCredential, https://example.org/examples#UniversityDegreeCredential]',
                  context: {
                    actual: [
                      'https://www.w3.org/2018/credentials#VerifiableCredential',
                      'https://example.org/examples#AlumniCredential',
                    ],
                    expected: [
                      ['https://example.org/examples#AlumniCredential', 'https://example.org/examples#BachelorDegree'],
                      [
                        'https://www.w3.org/2018/credentials#VerifiableCredential',
                        'https://example.org/examples#UniversityDegreeCredential',
                      ],
                    ],
                  },
                },
              ],
            },
            claims: {
              success: true,
              failed_claim_sets: undefined,
              valid_claim_sets: [
                {
                  success: true,
                  claim_set_index: undefined,
                  output: {
                    last_name: 'Dent',
                    first_name: 'Arthur',
                    address: {
                      street_address: '42 Market Street',
                    },
                  },
                  valid_claim_indexes: [0, 1, 2],
                },
              ],
              valid_claims: [
                {
                  success: true,
                  claim_id: undefined,
                  claim_index: 0,
                  output: {
                    last_name: 'Dent',
                  },
                },
                {
                  success: true,
                  claim_id: undefined,
                  claim_index: 1,
                  output: {
                    first_name: 'Arthur',
                  },
                },
                {
                  success: true,
                  claim_id: undefined,
                  claim_index: 2,
                  output: {
                    address: {
                      street_address: '42 Market Street',
                    },
                  },
                },
              ],
              failed_claims: undefined,
            },
          },
        ],
      },
    })
  })

  it('mdocMvrc example using namespaces succeeds', (_t) => {
    const query = DcqlQuery.parse(mdocNamespaceMvrcQuery)
    DcqlQuery.validate(query)

    const credentials = [mdocMvrc]
    const res = DcqlQuery.query(query, credentials)

    assert(res.can_be_satisfied)
    expect(res.credential_matches.my_credential.valid_credentials?.length).toEqual(1)
  })

  it('sdJwtDc example with multiple credentials succeeds', (_t) => {
    const query = DcqlQuery.parse(sdJwtDcExampleQuery)
    DcqlQuery.validate(query)

    const res = DcqlQuery.query(query, [exampleMdoc, exampleSdJwtDc])

    assert(res.can_be_satisfied)
    expect(res.credential_matches.my_credential.valid_credentials?.length).toEqual(1)
    expect(res.credential_matches.my_credential.failed_credentials?.length).toEqual(1)
  })

  it("sdJwtDc with 'multiple' set to true succeeds", (_t) => {
    const query = DcqlQuery.parse(sdJwtDcMultipleExampleQuery)
    DcqlQuery.validate(query)

    // We add the same credential twice
    const res = DcqlQuery.query(query, [exampleSdJwtDc, exampleSdJwtDc])

    assert(res.can_be_satisfied)

    const match = {
      success: true,
      input_credential_index: 0,
      trusted_authorities: {
        success: true,
      },
      meta: {
        success: true,
        output: {
          credential_format: 'dc+sd-jwt',
          cryptographic_holder_binding: false,
          vct: 'https://credentials.example.com/identity_credential',
        },
      },
      claims: {
        success: true,
        failed_claim_sets: undefined,
        valid_claim_sets: [
          {
            success: true,
            claim_set_index: undefined,
            output: {
              last_name: 'Dent',
              first_name: 'Arthur',
              address: {
                street_address: '42 Market Street',
              },
            },
            valid_claim_indexes: [0, 1, 2],
          },
        ],
        valid_claims: [
          {
            success: true,
            claim_id: undefined,
            claim_index: 0,
            output: {
              last_name: 'Dent',
            },
          },
          {
            success: true,
            claim_id: undefined,
            claim_index: 1,
            output: {
              first_name: 'Arthur',
            },
          },
          {
            success: true,
            claim_id: undefined,
            claim_index: 2,
            output: {
              address: {
                street_address: '42 Market Street',
              },
            },
          },
        ],
        failed_claims: undefined,
      },
    } as const
    assert.deepStrictEqual(res.credential_matches, {
      my_credential: {
        success: true,
        credential_query_id: 'my_credential',
        failed_credentials: undefined,

        // Match should be same except for credential index
        valid_credentials: [match, { ...match, input_credential_index: 1 }],
      },
    } as const)

    const presentationQueryResult = DcqlPresentationResult.fromDcqlPresentation(
      {
        my_credential: [exampleSdJwtDc, exampleSdJwtDc],
      },
      { dcqlQuery: query }
    )

    expect(presentationQueryResult.can_be_satisfied).toBe(true)
    expect(presentationQueryResult.credential_matches.my_credential.valid_credentials?.length).toEqual(2)
  })

  it("sdJwtDc with 'multiple' set to true but only one credential in the presentation matches", (_t) => {
    const query = DcqlQuery.parse(sdJwtDcMultipleExampleQuery)
    DcqlQuery.validate(query)

    // We add the same credential twice
    const res = DcqlQuery.query(query, [exampleSdJwtDc, exampleSdJwtDc])

    assert(res.can_be_satisfied)

    const presentationQueryResult = DcqlPresentationResult.fromDcqlPresentation(
      {
        my_credential: [exampleSdJwtDc, exampleMdoc],
      },
      { dcqlQuery: query }
    )
    expect(presentationQueryResult.can_be_satisfied).toBe(false)
  })

  it('sdJwtVc example succeeds', (_t) => {
    const query = DcqlQuery.parse(sdJwtVcQuery)
    DcqlQuery.validate(query)

    const credentials = [exampleSdJwtVc]
    const res = DcqlQuery.query(query, credentials)

    assert(res.can_be_satisfied)
    assert.deepStrictEqual(res.credential_matches, {
      my_credential: {
        success: true,
        credential_query_id: 'my_credential',
        failed_credentials: undefined,
        valid_credentials: [
          {
            success: true,
            input_credential_index: 0,
            trusted_authorities: {
              success: true,
            },
            meta: {
              success: true,
              output: {
                credential_format: 'vc+sd-jwt',
                cryptographic_holder_binding: true,
                type: [
                  'https://www.w3.org/ns/credentials/v2',
                  'https://example.org/examples#AlumniCredential',
                  'https://example.org/examples#BachelorDegree',
                ],
              },
            },
            claims: {
              success: true,
              failed_claim_sets: undefined,
              valid_claim_sets: [
                {
                  success: true,
                  claim_set_index: undefined,
                  output: {
                    last_name: 'Dent',
                    first_name: 'Arthur',
                    address: {
                      street_address: '42 Market Street',
                    },
                  },
                  valid_claim_indexes: [0, 1, 2],
                },
              ],
              valid_claims: [
                {
                  success: true,
                  claim_id: undefined,
                  claim_index: 0,
                  output: {
                    last_name: 'Dent',
                  },
                },
                {
                  success: true,
                  claim_id: undefined,
                  claim_index: 1,
                  output: {
                    first_name: 'Arthur',
                  },
                },
                {
                  success: true,
                  claim_id: undefined,
                  claim_index: 2,
                  output: {
                    address: {
                      street_address: '42 Market Street',
                    },
                  },
                },
              ],
              failed_claims: undefined,
            },
          },
        ],
      },
    })
  })

  it('sdJwtVc (legacy) example with multiple credentials succeeds', (_t) => {
    const query = DcqlQuery.parse(legacySdJwtVcExampleQuery)
    DcqlQuery.validate(query)

    const res = DcqlQuery.query(query, [exampleMdoc, exampleLegacySdJwtVc])

    assert(res.can_be_satisfied)
    expect(res.credential_matches.my_credential.valid_credentials?.length).toEqual(1)
    expect(res.credential_matches.my_credential.failed_credentials?.length).toEqual(1)
  })

  it("sdJwtVc (legacy) with 'multiple' set to true succeeds", (_t) => {
    const query = DcqlQuery.parse(legacySdJwtDcMultipleExampleQuery)
    DcqlQuery.validate(query)

    // We add the same credential twice
    const res = DcqlQuery.query(query, [exampleLegacySdJwtVc, exampleLegacySdJwtVc])

    assert(res.can_be_satisfied)

    const match = {
      success: true,
      input_credential_index: 0,
      trusted_authorities: {
        success: true,
      },
      meta: {
        success: true,
        output: {
          credential_format: 'vc+sd-jwt',
          cryptographic_holder_binding: false,
          vct: 'https://credentials.example.com/identity_credential',
        },
      },
      claims: {
        success: true,
        failed_claim_sets: undefined,
        valid_claim_sets: [
          {
            success: true,
            claim_set_index: undefined,
            output: {
              last_name: 'Dent',
              first_name: 'Arthur',
              address: {
                street_address: '42 Market Street',
              },
            },
            valid_claim_indexes: [0, 1, 2],
          },
        ],
        valid_claims: [
          {
            success: true,
            claim_id: undefined,
            claim_index: 0,
            output: {
              last_name: 'Dent',
            },
          },
          {
            success: true,
            claim_id: undefined,
            claim_index: 1,
            output: {
              first_name: 'Arthur',
            },
          },
          {
            success: true,
            claim_id: undefined,
            claim_index: 2,
            output: {
              address: {
                street_address: '42 Market Street',
              },
            },
          },
        ],
        failed_claims: undefined,
      },
    } as const
    assert.deepStrictEqual(res.credential_matches, {
      my_credential: {
        success: true,
        credential_query_id: 'my_credential',
        failed_credentials: undefined,

        // Match should be same except for credential index
        valid_credentials: [match, { ...match, input_credential_index: 1 }],
      },
    } as const)

    const presentationQueryResult = DcqlPresentationResult.fromDcqlPresentation(
      {
        my_credential: [exampleLegacySdJwtVc, exampleLegacySdJwtVc],
      },
      { dcqlQuery: query }
    )

    expect(presentationQueryResult.can_be_satisfied).toBe(true)
    expect(presentationQueryResult.credential_matches.my_credential.valid_credentials?.length).toEqual(2)
  })

  it("sdJwtVc (legacy) with 'multiple' set to true but only one credential in the presentation matches", (_t) => {
    const query = DcqlQuery.parse(legacySdJwtDcMultipleExampleQuery)
    DcqlQuery.validate(query)

    // We add the same credential twice
    const res = DcqlQuery.query(query, [exampleLegacySdJwtVc, exampleLegacySdJwtVc])

    assert(res.can_be_satisfied)

    const presentationQueryResult = DcqlPresentationResult.fromDcqlPresentation(
      {
        my_credential: [exampleLegacySdJwtVc, exampleMdoc],
      },
      { dcqlQuery: query }
    )
    expect(presentationQueryResult.can_be_satisfied).toBe(false)
  })

  it('throws a DcqlParseError with the issues of an invalid query', (_t) => {
    const parse = () =>
      DcqlQuery.parse({
        credentials: [
          {
            id: 'my credential',
            format: 'dc+sd-jwt',
            claims: [{ path: ['nationalities', -1] }],
            trusted_authorities: [{ type: 'aki', values: ['a+b'] }],
          },
          { format: 'mso_mdoc', claims: [{ path: ['org.iso.18013.5.1'] }] },
          { id: 'mvrc', format: 'mso_vc', claim_sets: [] },
        ],
      } as never)

    expect(parse).toThrow(DcqlParseError)
    expect(parse).toThrow(IdentityError)
    expect(parse).toThrow(
      expect.objectContaining({
        issues: [
          {
            severity: 'error',
            code: 'invalid_format',
            path: ['credentials', 0, 'id'],
            message: 'Expected a non-empty string of alphanumeric, underscore (_) or hyphen (-) characters',
            context: { format: 'regex' },
          },
          {
            severity: 'error',
            code: 'invalid_format',
            path: ['credentials', 0, 'trusted_authorities', 0, 'values', 0],
            message: 'aki trusted authority value must be base64url',
            context: { format: 'regex' },
          },
          {
            severity: 'error',
            code: 'invalid_type',
            path: ['credentials', 0, 'claims', 0, 'path', 1],
            message: 'Expected a string, a non-negative integer or null',
            context: { expected: 'a string, a non-negative integer or null' },
          },
          {
            severity: 'error',
            code: 'missing',
            path: ['credentials', 1, 'id'],
            message: 'Invalid input: expected string, received undefined',
          },
          {
            severity: 'error',
            code: 'invalid_type',
            path: ['credentials', 1, 'claims', 0, 'path'],
            message: 'Expected an array of two strings, a namespace and a data element identifier',
            context: { expected: 'an array of two strings, a namespace and a data element identifier' },
          },
          {
            severity: 'error',
            code: 'invalid_value',
            path: ['credentials', 2, 'format'],
            message: "Expected format to be one of 'mso_mdoc', 'dc+sd-jwt', 'vc+sd-jwt', 'jwt_vc_json' or 'ldp_vc'",
            context: {},
          },
        ],
      })
    )
  })

  it('reports an empty array that must not be empty', (_t) => {
    expect(() => DcqlQuery.parse({ credentials: [{ id: 'pid', format: 'dc+sd-jwt', claims: [] as never }] })).toThrow(
      expect.objectContaining({
        issues: [
          {
            severity: 'error',
            code: 'empty_array',
            path: ['credentials', 0, 'claims'],
            message: 'Array must be non-empty and have length of at least 1',
          },
        ],
      })
    )
  })

  it('reports duplicate and unknown ids with their location', (_t) => {
    const parse = () =>
      DcqlQuery.parse({
        credentials: [
          { id: 'pid', format: 'dc+sd-jwt' },
          {
            id: 'mdl',
            format: 'mso_mdoc',
            claims: [{ id: 'given_name', path: ['org.iso.18013.5.1', 'given_name'] }],
            claim_sets: [['given_name'], ['given_name', 'family_name']],
          },
          { id: 'pid', format: 'dc+sd-jwt' },
        ],
        credential_sets: [{ options: [['pid'], ['mdl', 'photo_id']] }],
      })

    expect(parse).toThrow(
      expect.objectContaining({
        issues: [
          {
            severity: 'error',
            code: 'unknown_claim_id',
            path: ['credentials', 1, 'claim_sets', 1, 1],
            message: "Claim set 1 refers to the claim id 'family_name', which is not in claims",
          },
          {
            severity: 'error',
            code: 'duplicate_credential_query_id',
            path: ['credentials', 2, 'id'],
            message: "The credential query id 'pid' is present more than once",
          },
          {
            severity: 'error',
            code: 'unknown_credential_query_id',
            path: ['credential_sets', 0, 'options', 1, 1],
            message: "Credential set 0 refers to the credential query id 'photo_id', which is not in credentials",
          },
        ],
      })
    )
  })

  it('validate reports the issues of a query that was not parsed', (_t) => {
    expect(() =>
      DcqlQuery.validate({
        credentials: [
          { id: 'pid', format: 'dc+sd-jwt', multiple: false, require_cryptographic_holder_binding: true },
          { id: 'pid', format: 'dc+sd-jwt', multiple: false, require_cryptographic_holder_binding: true },
        ],
      })
    ).toThrow(
      expect.objectContaining({
        issues: [expect.objectContaining({ code: 'duplicate_credential_query_id', path: ['credentials', 1, 'id'] })],
      })
    )
  })
})
