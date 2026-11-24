import { assert, describe, expect, test } from 'vitest'
import { DcqlPresentationResultError } from '../../dcql-error'
import { DcqlPresentation } from '../../dcql-presentation/m-dcql-presentation'
import { DcqlPresentationResult } from '../../dcql-presentation/m-dcql-presentation-result'
import { DcqlQuery } from '../../dcql-query'

describe('DCQL presentation with claim sets', () => {
  test('Correctly handles a presentation with one credential but the query requested two', () => {
    const dcqlQuery: DcqlQuery.Input = {
      credentials: [
        {
          id: 'c5d24076-71b1-4eb8-b3b2-1853a9f7e6b5',
          format: 'vc+sd-jwt',
          claims: [{ path: ['given_name'] }, { path: ['family_name'] }],
          meta: {
            vct_values: ['PersonIdentificationData'],
          },
        },
        {
          id: 'a50b7f9f-b5b1-4845-a7d3-3eb4830fdedc',
          format: 'vc+sd-jwt',
          claims: [{ path: ['expiry_date'] }, { path: ['document_number'] }],
          meta: {
            vct_values: ['MDL'],
          },
        },
      ],
    }

    const dcqlPresentation = {
      'c5d24076-71b1-4eb8-b3b2-1853a9f7e6b5': [
        {
          claims: {
            given_name: { foo: {} },
            family_name: { bar: {} },
          },
          credential_format: 'vc+sd-jwt' as const,
          vct: 'PersonIdentificationData',
          cryptographic_holder_binding: true,
        },
      ],
    }

    const parsedQuery = DcqlQuery.parse(dcqlQuery)
    DcqlQuery.validate(parsedQuery)

    const presentationQueryResult = DcqlPresentationResult.fromDcqlPresentation(dcqlPresentation, {
      dcqlQuery: parsedQuery,
    })

    expect(presentationQueryResult.can_be_satisfied).toEqual(false)
  })

  test('Correctly handles an SD-JWT VC presentation where a specific array index was requested, but presentation should not require the exact index due to possible array reordering with selective disclosure', () => {
    const dcqlQuery: DcqlQuery.Input = {
      credentials: [
        {
          id: 'c5d24076-71b1-4eb8-b3b2-1853a9f7e6b5',
          format: 'vc+sd-jwt',
          claims: [{ path: ['nationalities', 1], values: ['NL'] }],
        },
      ],
    }

    const dcqlPresentation = {
      'c5d24076-71b1-4eb8-b3b2-1853a9f7e6b5': [
        {
          claims: {
            // Only NL disclosed, so it's now at index 0 instead of the requested 1
            nationalities: ['NL'],
          },
          credential_format: 'vc+sd-jwt' as const,
          vct: 'PersonIdentificationData',
          cryptographic_holder_binding: true,
        },
      ],
    }

    const parsedQuery = DcqlQuery.parse(dcqlQuery)
    DcqlQuery.validate(parsedQuery)

    // For credential query it is not allowed, since the array index MUST match exactly
    const credentialQueryResult = DcqlQuery.query(parsedQuery, dcqlPresentation['c5d24076-71b1-4eb8-b3b2-1853a9f7e6b5'])
    assert(!credentialQueryResult.can_be_satisfied)

    const presentationQueryResult = DcqlPresentationResult.fromDcqlPresentation(dcqlPresentation, {
      dcqlQuery: parsedQuery,
    })

    // For presentations we allow the array ordering to be different
    assert(presentationQueryResult.can_be_satisfied)
  })

  test('Correctly handles a presentation with multiple claim sets where the first claim set matches', () => {
    const query: DcqlQuery.Input = {
      credentials: [
        {
          id: '8c791a1f-12b4-41fe-a892-236c2887fa8e',
          format: 'vc+sd-jwt',
          meta: { vct_values: ['PersonIdentificationData'] },
          claims: [
            { id: 'a', path: ['given_name'] },
            { id: 'b', path: ['family_name'] },
            { id: 'c', path: ['tax_id_code'] },
          ],
          claim_sets: [['c'], ['a', 'b']],
        },
      ],
    }

    const dcqlPresentation = {
      '8c791a1f-12b4-41fe-a892-236c2887fa8e': [
        {
          credential_format: 'vc+sd-jwt' as const,
          vct: 'PersonIdentificationData',
          cryptographic_holder_binding: true,
          claims: {
            tax_id_code: { baz: {} },
          },
        },
      ],
    }

    const parsedQuery = DcqlQuery.parse(query)
    DcqlQuery.validate(parsedQuery)

    const presentationQueryResult = DcqlPresentationResult.fromDcqlPresentation(dcqlPresentation, {
      dcqlQuery: parsedQuery,
    })

    expect(presentationQueryResult).toEqual({
      can_be_satisfied: true,
      credential_matches: {
        '8c791a1f-12b4-41fe-a892-236c2887fa8e': {
          success: true,
          credential_query_id: '8c791a1f-12b4-41fe-a892-236c2887fa8e',
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
                  vct: 'PersonIdentificationData',
                },
              },
              claims: {
                success: true,
                failed_claim_sets: [
                  {
                    claim_set_index: 1,
                    success: false,
                    issues: [
                      {
                        severity: 'error',
                        code: 'claims_path_not_found',
                        path: ['given_name'],
                        message: "Expected claim 'given_name' to be defined",
                      },
                      {
                        severity: 'error',
                        code: 'claims_path_not_found',
                        path: ['family_name'],
                        message: "Expected claim 'family_name' to be defined",
                      },
                    ],
                    failed_claim_indexes: [0, 1],
                    valid_claim_indexes: undefined,
                  },
                ],
                valid_claim_sets: [
                  {
                    claim_set_index: 0,
                    success: true,
                    output: {
                      tax_id_code: {
                        baz: {},
                      },
                    },
                    valid_claim_indexes: [2],
                  },
                ],
                valid_claims: [
                  {
                    success: true,
                    claim_index: 2,
                    claim_id: 'c',
                    output: {
                      tax_id_code: {
                        baz: {},
                      },
                    },
                  },
                ],
                failed_claims: [
                  {
                    success: false,
                    issues: [
                      {
                        severity: 'error',
                        code: 'claims_path_not_found',
                        path: ['given_name'],
                        message: "Expected claim 'given_name' to be defined",
                      },
                    ],
                    claim_index: 0,
                    claim_id: 'a',
                  },
                  {
                    success: false,
                    issues: [
                      {
                        severity: 'error',
                        code: 'claims_path_not_found',
                        path: ['family_name'],
                        message: "Expected claim 'family_name' to be defined",
                      },
                    ],
                    claim_index: 1,
                    claim_id: 'b',
                  },
                ],
              },
            },
          ],
        },
      },
      credential_sets: undefined,
    })
  })

  test('Correctly handles a presentation with multiple claim sets where the second claim set matches', () => {
    const query: DcqlQuery.Input = {
      credentials: [
        {
          id: '8c791a1f-12b4-41fe-a892-236c2887fa8e',
          format: 'vc+sd-jwt',
          meta: { vct_values: ['PersonIdentificationData'] },
          claims: [
            { id: 'a', path: ['given_name'] },
            { id: 'b', path: ['family_name'] },
            { id: 'c', path: ['tax_id_code'] },
          ],
          claim_sets: [['c'], ['a', 'b']],
        },
      ],
    }

    const dcqlPresentation = {
      '8c791a1f-12b4-41fe-a892-236c2887fa8e': [
        {
          credential_format: 'vc+sd-jwt' as const,
          vct: 'PersonIdentificationData',
          claims: {
            given_name: {
              foo: {},
            },
            family_name: {
              bar: {},
            },
          },
          cryptographic_holder_binding: true,
        },
      ],
    }

    const parsedQuery = DcqlQuery.parse(query)
    DcqlQuery.validate(parsedQuery)

    const presentationQueryResult = DcqlPresentationResult.fromDcqlPresentation(dcqlPresentation, {
      dcqlQuery: parsedQuery,
    })

    expect(presentationQueryResult).toEqual({
      can_be_satisfied: true,
      credential_matches: {
        '8c791a1f-12b4-41fe-a892-236c2887fa8e': {
          success: true,
          credential_query_id: '8c791a1f-12b4-41fe-a892-236c2887fa8e',
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
                  vct: 'PersonIdentificationData',
                },
              },
              claims: {
                success: true,
                failed_claim_sets: [
                  {
                    success: false,
                    issues: [
                      {
                        severity: 'error',
                        code: 'claims_path_not_found',
                        path: ['tax_id_code'],
                        message: "Expected claim 'tax_id_code' to be defined",
                      },
                    ],
                    claim_set_index: 0,
                    failed_claim_indexes: [2],
                    valid_claim_indexes: undefined,
                  },
                ],
                valid_claim_sets: [
                  {
                    success: true,
                    claim_set_index: 1,
                    output: {
                      given_name: {
                        foo: {},
                      },
                      family_name: {
                        bar: {},
                      },
                    },
                    valid_claim_indexes: [0, 1],
                  },
                ],
                valid_claims: [
                  {
                    success: true,
                    claim_index: 0,
                    claim_id: 'a',
                    output: {
                      given_name: {
                        foo: {},
                      },
                    },
                  },
                  {
                    success: true,
                    claim_index: 1,
                    claim_id: 'b',
                    output: {
                      family_name: {
                        bar: {},
                      },
                    },
                  },
                ],
                failed_claims: [
                  {
                    success: false,
                    issues: [
                      {
                        severity: 'error',
                        code: 'claims_path_not_found',
                        path: ['tax_id_code'],
                        message: "Expected claim 'tax_id_code' to be defined",
                      },
                    ],
                    claim_index: 2,
                    claim_id: 'c',
                  },
                ],
              },
            },
          ],
        },
      },
    })
  })

  test('Correctly handles a presentation with a credential set and multiple claim sets where the first credential set and second claim set matches', () => {
    const query: DcqlQuery.Input = {
      credentials: [
        {
          id: '8c791a1f-12b4-41fe-a892-236c2887fa8e',
          format: 'vc+sd-jwt',
          meta: { vct_values: ['PersonIdentificationData'] },
          claims: [
            { id: 'a', path: ['given_name'] },
            { id: 'b', path: ['family_name'] },
            { id: 'c', path: ['tax_id_code'] },
          ],
          claim_sets: [['c'], ['a', 'b']],
        },
      ],
      credential_sets: [
        {
          options: [['8c791a1f-12b4-41fe-a892-236c2887fa8e']],
          required: true,
        },
      ],
    }

    const dcqlPresentation = {
      '8c791a1f-12b4-41fe-a892-236c2887fa8e': [
        {
          credential_format: 'vc+sd-jwt' as const,
          vct: 'PersonIdentificationData',
          cryptographic_holder_binding: true,
          claims: {
            given_name: {
              foo: {},
            },
            family_name: {
              bar: {},
            },
          },
        },
      ],
    }

    const parsedQuery = DcqlQuery.parse(query)
    DcqlQuery.validate(parsedQuery)

    const presentationQueryResult = DcqlPresentationResult.fromDcqlPresentation(dcqlPresentation, {
      dcqlQuery: parsedQuery,
    })

    expect(presentationQueryResult).toEqual({
      can_be_satisfied: true,
      credential_sets: [
        {
          options: [['8c791a1f-12b4-41fe-a892-236c2887fa8e']],
          required: true,
          matching_options: [['8c791a1f-12b4-41fe-a892-236c2887fa8e']],
        },
      ],
      credential_matches: {
        '8c791a1f-12b4-41fe-a892-236c2887fa8e': {
          success: true,
          credential_query_id: '8c791a1f-12b4-41fe-a892-236c2887fa8e',
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
                  vct: 'PersonIdentificationData',
                  cryptographic_holder_binding: true,
                },
              },
              claims: {
                success: true,
                failed_claim_sets: [
                  {
                    success: false,
                    issues: [
                      {
                        severity: 'error',
                        code: 'claims_path_not_found',
                        path: ['tax_id_code'],
                        message: "Expected claim 'tax_id_code' to be defined",
                      },
                    ],
                    claim_set_index: 0,
                    failed_claim_indexes: [2],
                    valid_claim_indexes: undefined,
                  },
                ],
                valid_claim_sets: [
                  {
                    success: true,
                    claim_set_index: 1,
                    output: {
                      given_name: {
                        foo: {},
                      },
                      family_name: {
                        bar: {},
                      },
                    },
                    valid_claim_indexes: [0, 1],
                  },
                ],
                valid_claims: [
                  {
                    success: true,
                    claim_index: 0,
                    claim_id: 'a',
                    output: {
                      given_name: {
                        foo: {},
                      },
                    },
                  },
                  {
                    success: true,
                    claim_index: 1,
                    claim_id: 'b',
                    output: {
                      family_name: {
                        bar: {},
                      },
                    },
                  },
                ],
                failed_claims: [
                  {
                    success: false,
                    issues: [
                      {
                        severity: 'error',
                        code: 'claims_path_not_found',
                        path: ['tax_id_code'],
                        message: "Expected claim 'tax_id_code' to be defined",
                      },
                    ],
                    claim_index: 2,
                    claim_id: 'c',
                  },
                ],
              },
            },
          ],
        },
      },
    })
  })

  test('Correctly handles a presentation with multiple credential sets where credentials from an optional credential set are missing', () => {
    const query: DcqlQuery.Input = {
      credentials: [
        {
          id: '8c791a1f-12b4-41fe-a892-236c2887fa8e',
          format: 'vc+sd-jwt',
          meta: { vct_values: ['PersonIdentificationData'] },
          claims: [
            { id: 'a', path: ['given_name'] },
            { id: 'b', path: ['family_name'] },
            { id: 'c', path: ['tax_id_code'] },
          ],
          claim_sets: [['c'], ['a', 'b']],
        },
        {
          id: 'a46e92c0-847f-41f2-9218-2914e1d2388a',
          format: 'vc+sd-jwt',
          meta: { vct_values: ['SomeRandomVct'] },
          claims: [{ id: 'a', path: ['given_name'] }],
        },
      ],
      credential_sets: [
        {
          options: [['8c791a1f-12b4-41fe-a892-236c2887fa8e']],
          required: true,
        },
        {
          options: [['a46e92c0-847f-41f2-9218-2914e1d2388a']],
          required: false,
        },
      ],
    }

    const dcqlPresentation = {
      '8c791a1f-12b4-41fe-a892-236c2887fa8e': [
        {
          credential_format: 'vc+sd-jwt' as const,
          vct: 'PersonIdentificationData',
          claims: {
            given_name: { foo: {} },
            family_name: { bar: {} },
          },
          cryptographic_holder_binding: true,
        },
      ],
    }

    const parsedQuery = DcqlQuery.parse(query)
    DcqlQuery.validate(parsedQuery)

    const presentationQueryResult = DcqlPresentationResult.fromDcqlPresentation(dcqlPresentation, {
      dcqlQuery: parsedQuery,
    })

    expect(presentationQueryResult).toEqual({
      can_be_satisfied: true,
      credential_sets: [
        {
          options: [['8c791a1f-12b4-41fe-a892-236c2887fa8e']],
          required: true,
          matching_options: [['8c791a1f-12b4-41fe-a892-236c2887fa8e']],
        },
        {
          options: [['a46e92c0-847f-41f2-9218-2914e1d2388a']],
          required: false,
        },
      ],
      credential_matches: {
        '8c791a1f-12b4-41fe-a892-236c2887fa8e': {
          success: true,
          credential_query_id: '8c791a1f-12b4-41fe-a892-236c2887fa8e',
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
                  vct: 'PersonIdentificationData',
                },
              },
              claims: {
                success: true,
                failed_claim_sets: [
                  {
                    success: false,
                    issues: [
                      {
                        severity: 'error',
                        code: 'claims_path_not_found',
                        path: ['tax_id_code'],
                        message: "Expected claim 'tax_id_code' to be defined",
                      },
                    ],
                    claim_set_index: 0,
                    failed_claim_indexes: [2],
                    valid_claim_indexes: undefined,
                  },
                ],
                valid_claim_sets: [
                  {
                    success: true,
                    claim_set_index: 1,
                    output: {
                      given_name: {
                        foo: {},
                      },
                      family_name: {
                        bar: {},
                      },
                    },
                    valid_claim_indexes: [0, 1],
                  },
                ],
                valid_claims: [
                  {
                    success: true,
                    claim_index: 0,
                    claim_id: 'a',
                    output: {
                      given_name: {
                        foo: {},
                      },
                    },
                  },
                  {
                    success: true,
                    claim_index: 1,
                    claim_id: 'b',
                    output: {
                      family_name: {
                        bar: {},
                      },
                    },
                  },
                ],
                failed_claims: [
                  {
                    success: false,
                    issues: [
                      {
                        severity: 'error',
                        code: 'claims_path_not_found',
                        path: ['tax_id_code'],
                        message: "Expected claim 'tax_id_code' to be defined",
                      },
                    ],
                    claim_index: 2,
                    claim_id: 'c',
                  },
                ],
              },
            },
          ],
        },
      },
    })
  })

  test('Correctly handles a presentation with multiple credential sets where credentials from an optional credential set are provided but do not match the query', () => {
    const query: DcqlQuery.Input = {
      credentials: [
        {
          id: '8c791a1f-12b4-41fe-a892-236c2887fa8e',
          format: 'vc+sd-jwt',
          meta: { vct_values: ['PersonIdentificationData'] },
          claims: [
            { id: 'a', path: ['given_name'] },
            { id: 'b', path: ['family_name'] },
            { id: 'c', path: ['tax_id_code'] },
          ],
          claim_sets: [['c'], ['a', 'b']],
        },
        {
          id: 'a46e92c0-847f-41f2-9218-2914e1d2388a',
          format: 'vc+sd-jwt',
          meta: { vct_values: ['SomeRandomVct'] },
          claims: [{ id: 'a', path: ['given_name'] }],
        },
      ],
      credential_sets: [
        {
          options: [['8c791a1f-12b4-41fe-a892-236c2887fa8e']],
          required: true,
        },
        {
          options: [['a46e92c0-847f-41f2-9218-2914e1d2388a']],
          required: false,
        },
      ],
    }

    const dcqlPresentation = {
      '8c791a1f-12b4-41fe-a892-236c2887fa8e': [
        {
          credential_format: 'vc+sd-jwt' as const,
          vct: 'PersonIdentificationData',
          cryptographic_holder_binding: true,
          claims: {
            given_name: { foo: {} },
            family_name: { bar: {} },
          },
        },
      ],
      'a46e92c0-847f-41f2-9218-2914e1d2388a': [
        {
          credential_format: 'vc+sd-jwt' as const,
          vct: 'PersonIdentificationData',
          cryptographic_holder_binding: true,
          claims: {
            given_name: { foo: {} },
            family_name: { bar: {} },
          },
        },
      ],
    }

    const parsedQuery = DcqlQuery.parse(query)
    DcqlQuery.validate(parsedQuery)

    const presentationQueryResult = DcqlPresentationResult.fromDcqlPresentation(dcqlPresentation, {
      dcqlQuery: parsedQuery,
    })

    expect(presentationQueryResult).toEqual({
      can_be_satisfied: false,
      credential_sets: [
        {
          options: [['8c791a1f-12b4-41fe-a892-236c2887fa8e']],
          required: true,
          matching_options: [['8c791a1f-12b4-41fe-a892-236c2887fa8e']],
        },
        {
          matching_options: undefined,
          options: [['a46e92c0-847f-41f2-9218-2914e1d2388a']],
          required: false,
        },
      ],
      credential_matches: {
        '8c791a1f-12b4-41fe-a892-236c2887fa8e': {
          success: true,
          credential_query_id: '8c791a1f-12b4-41fe-a892-236c2887fa8e',
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
                  vct: 'PersonIdentificationData',
                },
              },
              claims: {
                success: true,
                failed_claim_sets: [
                  {
                    success: false,
                    issues: [
                      {
                        severity: 'error',
                        code: 'claims_path_not_found',
                        path: ['tax_id_code'],
                        message: "Expected claim 'tax_id_code' to be defined",
                      },
                    ],
                    claim_set_index: 0,
                    failed_claim_indexes: [2],
                    valid_claim_indexes: undefined,
                  },
                ],
                valid_claim_sets: [
                  {
                    success: true,
                    claim_set_index: 1,
                    output: {
                      given_name: {
                        foo: {},
                      },
                      family_name: {
                        bar: {},
                      },
                    },
                    valid_claim_indexes: [0, 1],
                  },
                ],
                valid_claims: [
                  {
                    success: true,
                    claim_index: 0,
                    claim_id: 'a',
                    output: {
                      given_name: {
                        foo: {},
                      },
                    },
                  },
                  {
                    success: true,
                    claim_index: 1,
                    claim_id: 'b',
                    output: {
                      family_name: {
                        bar: {},
                      },
                    },
                  },
                ],
                failed_claims: [
                  {
                    success: false,
                    issues: [
                      {
                        severity: 'error',
                        code: 'claims_path_not_found',
                        path: ['tax_id_code'],
                        message: "Expected claim 'tax_id_code' to be defined",
                      },
                    ],
                    claim_index: 2,
                    claim_id: 'c',
                  },
                ],
              },
            },
          ],
        },
        'a46e92c0-847f-41f2-9218-2914e1d2388a': {
          success: false,
          credential_query_id: 'a46e92c0-847f-41f2-9218-2914e1d2388a',
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
                    code: 'vct_mismatch',
                    path: ['vct'],
                    message: "Expected vct to be 'SomeRandomVct' but received 'PersonIdentificationData'",
                    context: { actual: 'PersonIdentificationData', expected: ['SomeRandomVct'] },
                  },
                ],
              },
              claims: {
                success: true,
                failed_claim_sets: undefined,
                valid_claim_sets: [
                  {
                    success: true,
                    output: {
                      given_name: {
                        foo: {},
                      },
                    },
                    valid_claim_indexes: [0],
                  },
                ],
                valid_claims: [
                  {
                    success: true,
                    claim_index: 0,
                    claim_id: 'a',
                    output: {
                      given_name: {
                        foo: {},
                      },
                    },
                  },
                ],
                failed_claims: undefined,
              },
            },
          ],
        },
      },
    })
  })

  test('Correctly handles a presentation without cryptographic binding but required in query', () => {
    const query: DcqlQuery.Input = {
      credentials: [
        {
          id: '8c791a1f-12b4-41fe-a892-236c2887fa8e',
          format: 'vc+sd-jwt',
          meta: { vct_values: ['PersonIdentificationData'] },
          claims: [{ path: ['given_name'] }],
        },
        {
          id: '5ff30b81-fd6b-4133-97c9-0c4520789e84',
          format: 'mso_mdoc',
          meta: { doctype_value: 'PersonIdentificationData' },
          claims: [{ path: ['namespace', 'given_name'] }],
          require_cryptographic_holder_binding: true,
        },
      ],
    }

    const dcqlPresentation = {
      '8c791a1f-12b4-41fe-a892-236c2887fa8e': {
        credential_format: 'vc+sd-jwt',
        vct: 'PersonIdentificationData',
        cryptographic_holder_binding: false,
        claims: {
          given_name: { foo: {} },
          family_name: { bar: {} },
        },
      },
      '5ff30b81-fd6b-4133-97c9-0c4520789e84': {
        credential_format: 'mso_mdoc',
        doctype: 'PersonIdentificationData',
        cryptographic_holder_binding: false,
        namespaces: {
          namespace: {
            given_name: 'foo',
            family_name: 'bar',
          },
        },
      },
    } as const

    const parsedQuery = DcqlQuery.parse(query)
    DcqlQuery.validate(parsedQuery)

    const presentationQueryResult = DcqlPresentationResult.fromDcqlPresentation(dcqlPresentation, {
      dcqlQuery: parsedQuery,
    })

    expect(
      presentationQueryResult.credential_matches['8c791a1f-12b4-41fe-a892-236c2887fa8e'].failed_credentials?.[0].meta
    ).toEqual({
      issues: [
        {
          severity: 'error',
          code: 'cryptographic_holder_binding_required',
          path: ['cryptographic_holder_binding'],
          message:
            "Expected cryptographic_holder_binding to be true (because credential query '8c791a1f-12b4-41fe-a892-236c2887fa8e' requires cryptographic holder binding), but received false",
        },
      ],
      success: false,
    })
  })
})

describe('DCQL presentation without a DCQL query', () => {
  test('parse only checks the structure of the vp_token', () => {
    // Without the query there are no credential query ids or 'multiple' to check the keys against
    expect(DcqlPresentation.parse({ unknown: ['presentation-1', 'presentation-2'] })).toEqual({
      unknown: ['presentation-1', 'presentation-2'],
    })
    expect(() => DcqlPresentation.parse({ pid: [] })).toThrow(
      expect.objectContaining({
        issues: [
          {
            severity: 'error',
            code: 'empty_array',
            path: ['pid'],
            message: 'Array must be non-empty and have length of at least 1',
          },
        ],
      })
    )
  })
})

// OpenID4VP 1.0 Sections 6.4.2 and 8.1: the rules for a vp_token that need no verification of its presentations
describe('DCQL presentation with a DCQL query', () => {
  const dcqlQuery = DcqlQuery.parse({
    credentials: [
      { id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['https://example.com/pid'] } },
      { id: 'mdl', format: 'mso_mdoc', meta: { doctype_value: 'org.iso.18013.5.1.mDL' }, multiple: true },
    ],
  })

  test('parse accepts one presentation for a credential query, and more for one with multiple', () => {
    const presentation = { pid: ['pid-presentation'], mdl: ['mdl-presentation-1', 'mdl-presentation-2'] }

    expect(DcqlPresentation.parse(presentation, { dcqlQuery })).toEqual(presentation)
  })

  test('fromDcqlPresentation reports a credential query id that is not in the query with the message of parse', () => {
    const pidPresentation = {
      credential_format: 'dc+sd-jwt' as const,
      vct: 'https://example.com/pid',
      claims: {},
      cryptographic_holder_binding: true,
    }

    expect(() => DcqlPresentationResult.fromDcqlPresentation({ photo_id: [pidPresentation] }, { dcqlQuery })).toThrow(
      new DcqlPresentationResultError({
        message: "The presentation refers to the credential query id 'photo_id', which is not in 'credentials'",
      })
    )
  })

  test('parse checks a JSON encoded vp_token against the query', () => {
    const presentation = { pid: ['pid-presentation'], mdl: ['mdl-presentation'] }
    expect(DcqlPresentation.parse(JSON.stringify(presentation), { dcqlQuery })).toEqual(presentation)

    expect(() =>
      DcqlPresentation.parse(JSON.stringify({ pid: ['pid-presentation'], photo_id: ['photo-id-presentation'] }), {
        dcqlQuery,
      })
    ).toThrow(
      expect.objectContaining({
        issues: [
          {
            severity: 'error',
            code: 'unknown_credential_query_id',
            path: ['photo_id'],
            message: "The presentation refers to the credential query id 'photo_id', which is not in 'credentials'",
          },
          {
            severity: 'error',
            code: 'missing_value',
            path: ['mdl'],
            message: "Expected a presentation for the credential query 'mdl'",
            context: { expected: 'array' },
          },
        ],
      })
    )
  })

  test('parse reports more than one presentation without multiple, an id that is not a credential query, and a credential query without a presentation', () => {
    expect(() =>
      DcqlPresentation.parse(
        { pid: ['pid-presentation-1', 'pid-presentation-2'], photo_id: ['photo-id-presentation'] },
        { dcqlQuery }
      )
    ).toThrow(
      expect.objectContaining({
        issues: [
          {
            severity: 'error',
            code: 'multiple_presentations_not_allowed',
            path: ['pid'],
            message: "Credential query 'pid' has 2 presentations, but allows only one without 'multiple'",
          },
          {
            severity: 'error',
            code: 'unknown_credential_query_id',
            path: ['photo_id'],
            message: "The presentation refers to the credential query id 'photo_id', which is not in 'credentials'",
          },
          {
            severity: 'error',
            code: 'missing_value',
            path: ['mdl'],
            message: "Expected a presentation for the credential query 'mdl'",
            context: { expected: 'array' },
          },
        ],
      })
    )
  })

  test('parse reports the first presentation of each credential query that is not the JSON type of its format', () => {
    const query = DcqlQuery.parse({
      credentials: [
        ...dcqlQuery.credentials,
        { id: 'diploma', format: 'ldp_vc', meta: { type_values: [['https://example.com/Diploma']] } },
        { id: 'membership', format: 'jwt_vc_json', meta: { type_values: [['https://example.com/Membership']] } },
        { id: 'legacy_pid', format: 'vc+sd-jwt', meta: { vct_values: ['https://example.com/pid'] } },
      ],
    })

    expect(() =>
      DcqlPresentation.parse(
        {
          pid: [{ presentation: 'as an object' }],
          mdl: ['mdl-presentation', { presentation: 'as an object' }, { presentation: 'as an object' }],
          diploma: ['diploma-presentation'],
          membership: [{ presentation: 'as an object' }],
          legacy_pid: [{ presentation: 'as an object' }],
        },
        { dcqlQuery: query }
      )
    ).toThrow(
      expect.objectContaining({
        issues: [
          {
            severity: 'error',
            code: 'invalid_type',
            path: ['pid', 0],
            message: "Expected a presentation of format 'dc+sd-jwt' to be a string",
            context: { expected: 'string' },
          },
          {
            severity: 'error',
            code: 'invalid_type',
            path: ['mdl', 1],
            message: "Expected a presentation of format 'mso_mdoc' to be a string",
            context: { expected: 'string' },
          },
          {
            severity: 'error',
            code: 'invalid_type',
            path: ['diploma', 0],
            message: "Expected a presentation of format 'ldp_vc' to be an object",
            context: { expected: 'object' },
          },
          {
            severity: 'error',
            code: 'invalid_type',
            path: ['membership', 0],
            message: "Expected a presentation of format 'jwt_vc_json' to be a string",
            context: { expected: 'string' },
          },
          {
            severity: 'error',
            code: 'invalid_type',
            path: ['legacy_pid', 0],
            message: "Expected a presentation of format 'vc+sd-jwt' to be a string",
            context: { expected: 'string' },
          },
        ],
      })
    )

    // A presentation that is not in an array, as in earlier drafts, is reported at its credential query id
    expect(() =>
      DcqlPresentation.parse(
        { pid: { presentation: 'as an object' } },
        { dcqlQuery: DcqlQuery.parse({ credentials: [dcqlQuery.credentials[0]] }) }
      )
    ).toThrow(
      expect.objectContaining({
        issues: [
          {
            severity: 'error',
            code: 'invalid_type',
            path: ['pid'],
            message: "Expected a presentation of format 'dc+sd-jwt' to be a string",
            context: { expected: 'string' },
          },
        ],
      })
    )
  })

  test('parse reports a required credential set without an option that has a presentation for each of its credential queries', () => {
    const query = DcqlQuery.parse({
      credentials: [
        ...dcqlQuery.credentials,
        { id: 'photo_id', format: 'dc+sd-jwt', meta: { vct_values: ['https://example.com/photo_id'] } },
      ],
      credential_sets: [{ options: [['pid'], ['mdl']] }, { required: false, options: [['photo_id']] }],
    })

    expect(DcqlPresentation.parse({ mdl: ['mdl-presentation'] }, { dcqlQuery: query })).toEqual({
      mdl: ['mdl-presentation'],
    })
    expect(() => DcqlPresentation.parse({ photo_id: ['photo-id-presentation'] }, { dcqlQuery: query })).toThrow(
      expect.objectContaining({
        issues: [
          {
            severity: 'error',
            code: 'unsatisfied_credential_set',
            path: [],
            message:
              'Credential set 0 is required, but none of its options has a presentation for each of its credential queries',
          },
        ],
      })
    )

    // An option is only satisfied with a presentation for each of its credential queries
    const queryWithPairedOption = DcqlQuery.parse({
      credentials: dcqlQuery.credentials,
      credential_sets: [{ options: [['pid', 'mdl']] }],
    })
    expect(() => DcqlPresentation.parse({ pid: ['pid-presentation'] }, { dcqlQuery: queryWithPairedOption })).toThrow(
      expect.objectContaining({
        issues: [
          {
            severity: 'error',
            code: 'unsatisfied_credential_set',
            path: [],
            message:
              'Credential set 0 is required, but none of its options has a presentation for each of its credential queries',
          },
        ],
      })
    )
  })
})
