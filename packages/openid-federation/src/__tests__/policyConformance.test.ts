import { describe, expect, it } from 'vitest'
import type { EntityStatementClaims } from '../entityStatement'
import { type Metadata, type MetadataPolicyOperator, metadataPolicySchema } from '../metadata'
import {
  applyMetadataPolicyToMetadata,
  combineMetadataPolicies,
  PolicyValidationError,
} from '../resolveTrustChains/policies'
import { combineExistingMetadataPolicyOperators } from '../resolveTrustChains/policies/combineExistingMetadataPolicyOperators'

// The rules of OpenID Federation 1.0 final, Section 6.1, https://openid.net/specs/openid-federation-1_0.html#section-6.1

const apply = (leafMetadata: Record<string, Record<string, unknown>>, policy: Record<string, MetadataPolicyOperator>) =>
  applyMetadataPolicyToMetadata({
    leafMetadata: leafMetadata as Metadata,
    policyMetadata: { openid_relying_party: policy },
  }).resolvedLeafMetadata as Record<string, Record<string, unknown>>

const merge = (existingPolicyRules: MetadataPolicyOperator, newPolicyRules: MetadataPolicyOperator) =>
  combineExistingMetadataPolicyOperators({
    contextPath: 'openid_relying_party.grant_types',
    existingPolicyRules,
    newPolicyRules,
  })

const statement = (metadataPolicy: Record<string, Record<string, MetadataPolicyOperator>>) =>
  ({ metadata_policy: metadataPolicy }) as unknown as EntityStatementClaims

const rp = { openid_relying_party: { client_name: 'RP' } }

describe('metadata policy application (Section 6.1.3.1)', () => {
  // Section 6.1.3.1.5 subset_of: "If the metadata parameter is present, it is assigned the intersection between the
  // values of the operator and the metadata parameter."
  it('subset_of has no effect when the metadata parameter is absent', () => {
    expect(apply(rp, { grant_types: { subset_of: ['authorization_code'] } })).toStrictEqual(rp)
  })

  // Section 6.1.3.1.6 superset_of: "If the metadata parameter is present, its values MUST contain those specified in
  // the operator value."
  it('superset_of has no effect when the metadata parameter is absent', () => {
    expect(apply(rp, { grant_types: { superset_of: ['authorization_code'] } })).toStrictEqual(rp)
  })

  // Section 6.1.3.1.4 one_of: "If the metadata parameter is present, its value MUST be one of those listed in the
  // operator value."
  it('one_of has no effect when the metadata parameter is absent', () => {
    expect(apply(rp, { token_endpoint_auth_method: { one_of: ['private_key_jwt'] } })).toStrictEqual(rp)
  })

  // Section 6.1.3.1.6 superset_of: "its values MUST contain those specified in the operator value. By mathematically
  // defining supersets, equality is included."
  it('superset_of requires the metadata parameter to contain every operator value', () => {
    const metadata = { openid_relying_party: { grant_types: ['authorization_code', 'refresh_token'] } }
    expect(apply(metadata, { grant_types: { superset_of: ['authorization_code'] } })).toStrictEqual(metadata)
    expect(apply(metadata, { grant_types: { superset_of: ['authorization_code', 'refresh_token'] } })).toStrictEqual(
      metadata
    )
    expect(() => apply(metadata, { grant_types: { superset_of: ['authorization_code', 'implicit'] } })).toThrow(
      PolicyValidationError
    )
  })

  // Section 6.1.3.1.5 subset_of: "Note that the resulting intersection may thus be an empty array []."
  // Section 6.1.3.1.8, Table 1: essential true, subset_of [a,b,c], input [d,e], output [].
  it('subset_of with an empty intersection leaves an empty array, also when essential', () => {
    const metadata = { openid_relying_party: { grant_types: ['d', 'e'] } }
    expect(apply(metadata, { grant_types: { subset_of: ['a', 'b', 'c'], essential: true } })).toStrictEqual({
      openid_relying_party: { grant_types: [] },
    })
    expect(apply(metadata, { grant_types: { subset_of: ['a', 'b', 'c'], essential: false } })).toStrictEqual({
      openid_relying_party: { grant_types: [] },
    })
  })

  // Section 6.1.3.1.8, Table 1: essential true, subset_of [a,b,c], no parameter, error; essential false, no parameter,
  // no parameter.
  it('subset_of with essential follows Table 1 when the metadata parameter is absent', () => {
    expect(() => apply(rp, { grant_types: { subset_of: ['a', 'b', 'c'], essential: true } })).toThrow(
      PolicyValidationError
    )
    expect(apply(rp, { grant_types: { subset_of: ['a', 'b', 'c'], essential: false } })).toStrictEqual(rp)
  })

  // Section 6.1.3.1.2 add: "If the metadata parameter is absent, it MUST be initialized with the value of this
  // operator."
  it('add initializes an absent metadata parameter of an entity type the metadata has', () => {
    expect(apply(rp, { contacts: { add: ['ops@example.org'] } })).toStrictEqual({
      openid_relying_party: { client_name: 'RP', contacts: ['ops@example.org'] },
    })
  })

  // Section 6.1.4.2: "for every Entity Type metadata and metadata parameter for which a corresponding metadata
  // parameter policy is present, the included policy operators MUST be applied"
  it('does not add an entity type the metadata does not have', () => {
    const metadata = { federation_entity: { organization_name: 'Org' } }
    expect(
      apply(metadata, {
        contacts: { add: ['ops@example.org'] },
        client_name: { default: 'RP' },
        subject_type: { value: 'pairwise' },
        id_token_signed_response_alg: { essential: true },
      })
    ).toStrictEqual(metadata)
  })

  // Section 6.1.3.1.8: "The scope OAuth 2.0 client metadata parameter, defined in [RFC7591] and represented by a string
  // of space-separated string values, is to be regarded and processed as a string array by policy operators"
  it('processes scope as a string array', () => {
    const metadata = { openid_relying_party: { scope: 'openid profile email' } }
    expect(
      apply(metadata, { scope: { subset_of: ['openid', 'email', 'phone'], superset_of: ['openid'] } })
    ).toStrictEqual({
      openid_relying_party: { scope: 'openid email' },
    })
    expect(apply(metadata, { scope: { add: ['phone'] } })).toStrictEqual({
      openid_relying_party: { scope: 'openid profile email phone' },
    })
    expect(apply(rp, { scope: { default: 'openid' } })).toStrictEqual({
      openid_relying_party: { client_name: 'RP', scope: 'openid' },
    })
    expect(() => apply(metadata, { scope: { superset_of: ['phone'] } })).toThrow(PolicyValidationError)
  })

  // Section 3.1.1 metadata: "even if the values are the empty JSON object {}"
  it('keeps an entity type whose last metadata parameter value null removes', () => {
    const metadata = { openid_relying_party: { subject_type: 'public' } }
    expect(apply(metadata, { subject_type: { value: null } })).toStrictEqual({ openid_relying_party: {} })
  })
})

describe('metadata policy merge (Section 6.1.3.1)', () => {
  // Section 6.1.3.1.7 essential: "The result of merging the values of two essential operators is the logical
  // disjunction (OR) of the operator values."
  it('merges essential with a logical OR', () => {
    expect(merge({ essential: false }, { essential: true })).toStrictEqual({ essential: true })
    expect(merge({ essential: true }, { essential: false })).toStrictEqual({ essential: true })
    expect(merge({ essential: false }, { essential: false })).toStrictEqual({ essential: false })
  })

  // Section 6.1.3.1.5 subset_of: "The result of merging the values of two subset_of operators is the intersection of
  // the operator values. Note that the resulting intersection may thus be an empty array []."
  it('merges subset_of without common values to an empty array, which a later subset_of does not widen', () => {
    const empty = merge({ subset_of: ['a'] }, { subset_of: ['b'] })
    expect(empty).toStrictEqual({ subset_of: [] })
    expect(merge(empty, { subset_of: ['a', 'b'] })).toStrictEqual({ subset_of: [] })
  })

  // Section 6.1.3.1.4 one_of: "If the intersection is empty, this MUST result in a policy error."
  it('refuses to merge one_of without common values', () => {
    expect(() => merge({ one_of: ['a'] }, { one_of: ['b'] })).toThrow()
  })

  // Section 6.1.4.1: "Subordinate operators that are not present in the current metadata parameter policy MUST be
  // copied to it." Combined with Section 6.1.3.1.1 value: "MAY be combined with subset_of".
  it('merges value of a superior with subset_of of a subordinate', () => {
    const { mergedPolicy } = combineMetadataPolicies({
      statements: [
        statement({ openid_relying_party: { grant_types: { subset_of: ['authorization_code', 'refresh_token'] } } }),
        statement({ openid_relying_party: { grant_types: { value: ['authorization_code'] } } }),
      ],
    })
    expect(mergedPolicy).toStrictEqual({
      openid_relying_party: {
        grant_types: { value: ['authorization_code'], subset_of: ['authorization_code', 'refresh_token'] },
      },
    })
  })

  // Section 6.1.4.1: "If the resulting metadata parameter policy contains combinations that are not allowed, as
  // described in Section 6.1.3 and in accordance with the specifications of the operators, this MUST produce a policy
  // error."
  it('refuses a merged policy whose combination is not allowed', () => {
    expect(() =>
      combineMetadataPolicies({
        statements: [
          statement({ openid_relying_party: { grant_types: { superset_of: ['implicit'] } } }),
          statement({ openid_relying_party: { grant_types: { subset_of: ['authorization_code'] } } }),
        ],
      })
    ).toThrow()
  })
})

describe('metadata policy operator combinations (Section 6.1.3.1)', () => {
  const allowed = (policy: Record<string, unknown>) => metadataPolicySchema.safeParse(policy).success

  // Section 6.1.3.1.1 value: "MAY be combined with add, in which case the values of add MUST be a subset of the values
  // of value."
  it('value with add', () => {
    expect(allowed({ value: ['a', 'b'], add: ['a'] })).toBeTruthy()
    expect(!allowed({ value: ['a'], add: ['b'] })).toBeTruthy()
  })

  // Section 6.1.3.1.1 value: "MAY be combined with default if the value of value is not null."
  it('value with default', () => {
    expect(allowed({ value: 'a', default: 'b' })).toBeTruthy()
    expect(!allowed({ value: null, default: 'b' })).toBeTruthy()
  })

  // Section 6.1.3.1.1 value: "MAY be combined with one_of, in which case the value of value MUST be among the one_of
  // values."
  it('value with one_of', () => {
    expect(allowed({ value: 'a', one_of: ['a', 'b'] })).toBeTruthy()
    expect(!allowed({ value: 'c', one_of: ['a', 'b'] })).toBeTruthy()
  })

  // Section 6.1.3.1.1 value: "MAY be combined with subset_of, in which case the values of value MUST be a subset of the
  // values of subset_of."
  it('value with subset_of', () => {
    expect(allowed({ value: ['a'], subset_of: ['a', 'b'] })).toBeTruthy()
    expect(!allowed({ value: ['c'], subset_of: ['a', 'b'] })).toBeTruthy()
  })

  // Section 6.1.3.1.1 value: "MAY be combined with superset_of, in which case the values of value MUST be a superset of
  // the values of superset_of."
  it('value with superset_of', () => {
    expect(allowed({ value: ['a', 'b'], superset_of: ['a'] })).toBeTruthy()
    expect(!allowed({ value: ['a'], superset_of: ['a', 'b'] })).toBeTruthy()
  })

  // Section 6.1.3.1.1 value: the only conditions on a null value are for default and essential. A null value removes
  // the metadata parameter, so it has no values: a subset of any subset_of, a superset only of an empty superset_of.
  it('value null with subset_of, superset_of and add', () => {
    expect(allowed({ value: null, subset_of: ['a'] })).toBeTruthy()
    expect(allowed({ value: null, superset_of: [] })).toBeTruthy()
    expect(!allowed({ value: null, superset_of: ['a'] })).toBeTruthy()
    expect(!allowed({ value: null, add: ['a'] })).toBeTruthy()
  })

  // Section 6.1.3.1.1 value: "MAY be combined with essential, except when value is null and essential is true."
  it('value with essential', () => {
    expect(allowed({ value: null, essential: false })).toBeTruthy()
    expect(allowed({ value: 'a', essential: true })).toBeTruthy()
    expect(!allowed({ value: null, essential: true })).toBeTruthy()
  })

  // Section 6.1.3.1.2 add: "MAY be combined with subset_of, in which case the values of add MUST be a subset of the
  // values of subset_of."
  it('add with subset_of', () => {
    expect(allowed({ add: ['a'], subset_of: ['a', 'b'] })).toBeTruthy()
    expect(!allowed({ add: ['c'], subset_of: ['a', 'b'] })).toBeTruthy()
  })

  // Section 6.1.3.1.5 subset_of: "MAY be combined with superset_of, in which case the values of subset_of MUST be a
  // superset of the values of superset_of."
  it('subset_of with superset_of', () => {
    expect(allowed({ subset_of: ['a', 'b'], superset_of: ['a'] })).toBeTruthy()
    expect(!allowed({ subset_of: ['a'], superset_of: ['a', 'b'] })).toBeTruthy()
  })

  // Section 6.1.3.1.4 one_of: "MAY be combined with value", "MAY be combined with default", "MAY be combined with
  // essential." (and nothing else)
  it('one_of with operators it may not be combined with', () => {
    expect(!allowed({ one_of: ['a'], subset_of: ['a'] })).toBeTruthy()
    expect(!allowed({ one_of: ['a'], add: ['a'] })).toBeTruthy()
  })

  // Section 6.1.3.2: "Implementations MUST ignore additional operators that are not understood, unless the operator
  // name is included in the metadata_policy_crit Subordinate Statement Claim"
  it('ignores additional operators when checking combinations', () => {
    expect(allowed({ value: 'a', regexp: '^a$' })).toBeTruthy()
  })
})
