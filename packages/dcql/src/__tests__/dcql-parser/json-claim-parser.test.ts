import { describe, expect, it } from 'vitest'
import { getJsonClaimParser } from '../../dcql-parser/dcql-claims-query-result.js'
import { DcqlNotDisclosed } from '../../u-dcql.js'

const claimsPathPointerExample = {
  name: 'Arthur Dent',
  middle_name: null,
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
  nullable_list: ['first', null, 'third'],
}

describe('Json Claim Parser', () => {
  it('name', (_t) => {
    const parser = getJsonClaimParser(
      { path: ['name'] },
      {
        index: 0,
        presentation: false,
      }
    )
    const res = parser.parse(claimsPathPointerExample)

    expect(res).toEqual({ name: 'Arthur Dent' })
  })

  it('middle_name with literal null value', (_t) => {
    const parser = getJsonClaimParser(
      { path: ['middle_name'] },
      {
        index: 0,
        presentation: false,
      }
    )
    const res = parser.parse(claimsPathPointerExample)

    expect(res).toEqual({ middle_name: null })
  })

  it('address', (_t) => {
    const parser = getJsonClaimParser(
      { path: ['address'] },
      {
        presentation: false,
        index: 0,
      }
    )
    const res = parser.parse(claimsPathPointerExample)

    expect(res).toEqual({
      address: {
        street_address: '42 Market Street',
        locality: 'Milliways',
        postal_code: '12345',
      },
    })
  })

  it('address street address', (_t) => {
    const parser = getJsonClaimParser({ path: ['address', 'street_address'] }, { presentation: false, index: 0 })
    const res = parser.parse(claimsPathPointerExample)

    expect(res).toEqual({
      address: {
        street_address: '42 Market Street',
      },
    })
  })

  it('nationalities', (_t) => {
    const parser = getJsonClaimParser(
      { path: ['nationalities', 1] },
      {
        presentation: false,
        index: 0,
      }
    )
    const res = parser.parse(claimsPathPointerExample)

    expect(res).toEqual({
      nationalities: [DcqlNotDisclosed, 'Betelgeusian'],
    })
  })

  it('nullable_list with literal null element', (_t) => {
    const parser = getJsonClaimParser(
      { path: ['nullable_list', 1] },
      {
        presentation: false,
        index: 0,
      }
    )
    const res = parser.parse(claimsPathPointerExample)

    expect(res).toEqual({
      nullable_list: [DcqlNotDisclosed, null],
    })
  })

  it('all degree types', (_t) => {
    const parser = getJsonClaimParser(
      { path: ['degrees', null, 'type'] },
      {
        presentation: false,
        index: 0,
      }
    )
    const res = parser.parse(claimsPathPointerExample)

    expect(res).toEqual({
      degrees: [{ type: 'Bachelor of Science' }, { type: 'Master of Science' }],
    })
  })

  it('all nationalities with path null query', (_t) => {
    const parser = getJsonClaimParser(
      { path: ['nationalities', null] },
      {
        presentation: false,
        index: 0,
      }
    )
    const res = parser.parse(claimsPathPointerExample)

    expect(res).toEqual({
      nationalities: ['British', 'Betelgeusian'],
    })
  })

  it('all nationalities with path null query with values', (_t) => {
    const parser = getJsonClaimParser(
      { path: ['nationalities', null], values: ['British', 'Something'] },
      {
        presentation: false,
        index: 0,
      }
    )
    const res = parser.parse(claimsPathPointerExample)

    expect(res).toEqual({
      nationalities: ['British', DcqlNotDisclosed],
    })
  })

  it('all items from first nationality results in error due to nationality not being an array', (_t) => {
    const parser = getJsonClaimParser(
      { path: ['nationalities', 0, null], values: ['British', 'Something'] },
      {
        presentation: false,
        index: 0,
      }
    )
    const res = parser.safeParse(claimsPathPointerExample)
    expect(res.error?.issues[0].message).toEqual("Expected path 'nationalities'.0.null to be an array")
  })

  it('all items from first nationality results in error due to nationality not being an array', (_t) => {
    const parser = getJsonClaimParser(
      { path: ['nationalities', 0, null], values: ['British', 'Something'] },
      {
        presentation: true,
        index: 0,
      }
    )
    const res = parser.safeParse(claimsPathPointerExample)
    expect(res.error?.issues[0].message).toEqual(
      "Expected any element in array 'nationalities'.0 to match sub requirement but none matched: Expected path 'nationalities'.0.null to be an array"
    )
  })

  it('fails without throwing for an empty array in a presentation', (_t) => {
    const parser = getJsonClaimParser({ path: ['nationalities', 0] }, { presentation: true, index: 0 })
    const res = parser.safeParse({ nationalities: [] })

    expect(res.error?.issues).toMatchObject([
      {
        path: ['nationalities'],
        message: "Expected any element in array 'nationalities'.0 to match, but the array is empty",
      },
    ])
  })
})
