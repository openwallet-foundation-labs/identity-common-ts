import { describe, expect, it } from 'vitest'
import { addTrustedEntity, createLoTE, removeTrustedEntity, service, trustedEntity, updateLoTEVersion } from '../index'
import type { TrustedEntity } from '../types'

describe('LoTE Creation', () => {
  const minimalSchemeInfo = {
    SchemeOperatorName: [{ lang: 'en', value: 'Test Operator' }],
  }

  const fullSchemeInfo = {
    SchemeOperatorName: [{ lang: 'en', value: 'Test Operator' }],
    SchemeOperatorAddress: {
      SchemeOperatorPostalAddress: [
        {
          lang: 'en',
          StreetAddress: '123 Test St',
          Locality: 'Test City',
          PostalCode: '12345',
          Country: 'DE',
        },
      ],
      SchemeOperatorElectronicAddress: [{ lang: 'en', uriValue: 'mailto:test@example.com' }],
    },
    SchemeName: [{ lang: 'en', value: 'Test Scheme' }],
    SchemeTerritory: 'DE',
  }

  it('should create a minimal LoTE document with only required fields', () => {
    const lote = createLoTE(minimalSchemeInfo)

    expect(lote.LoTE).toBeDefined()
    expect(lote.LoTE.ListAndSchemeInformation).toBeDefined()
    expect(lote.LoTE.ListAndSchemeInformation.SchemeOperatorName).toEqual([{ lang: 'en', value: 'Test Operator' }])
    expect(lote.LoTE.ListAndSchemeInformation.LoTEVersionIdentifier).toBe(1)
    expect(lote.LoTE.ListAndSchemeInformation.LoTESequenceNumber).toBe(1)
    // No entities: no TrustedEntitiesList key (the JSON schema has minItems 1)
    expect('TrustedEntitiesList' in lote.LoTE).toBe(false)
  })

  it('should create a LoTE document with full scheme info', () => {
    const lote = createLoTE(fullSchemeInfo)

    expect(lote.LoTE.ListAndSchemeInformation.SchemeName).toEqual([{ lang: 'en', value: 'Test Scheme' }])
    expect(lote.LoTE.ListAndSchemeInformation.SchemeTerritory).toBe('DE')
    expect(lote.LoTE.ListAndSchemeInformation.SchemeOperatorAddress).toBeDefined()
  })

  it('should auto-generate ListIssueDateTime and NextUpdate with 6-month default per ETSI spec', () => {
    const beforeCreate = new Date()
    const lote = createLoTE(minimalSchemeInfo)
    const issueDate = new Date(lote.LoTE.ListAndSchemeInformation.ListIssueDateTime)
    const nextUpdate = new Date(lote.LoTE.ListAndSchemeInformation.NextUpdate)

    expect(issueDate.getTime()).toBeLessThanOrEqual(Date.now())
    expect(issueDate.getTime()).toBeGreaterThanOrEqual(beforeCreate.getTime())

    // NextUpdate should be approximately 6 months after issue date
    const expectedNextUpdate = new Date(issueDate)
    expectedNextUpdate.setMonth(expectedNextUpdate.getMonth() + 6)
    expect(nextUpdate.getTime()).toBe(expectedNextUpdate.getTime())
  })

  it('should accept custom ListIssueDateTime and NextUpdate', () => {
    const customDate = '2024-01-01T00:00:00.000Z'
    const customNextUpdate = '2025-01-01T00:00:00.000Z'

    const lote = createLoTE({
      ...minimalSchemeInfo,
      ListIssueDateTime: customDate,
      NextUpdate: customNextUpdate,
    })

    expect(lote.LoTE.ListAndSchemeInformation.ListIssueDateTime).toBe(customDate)
    expect(lote.LoTE.ListAndSchemeInformation.NextUpdate).toBe(customNextUpdate)
  })

  it('should create LoTE document with initial entities', () => {
    const entity = trustedEntity()
      .name('Test Entity')
      .postalAddress({
        StreetAddress: '456 Entity St',
        Locality: 'Entity City',
        PostalCode: '67890',
        Country: 'DE',
      })
      .email('entity@example.com')
      .addService(
        service()
          .name('Test Service')
          .addPublicKey({
            kty: 'EC',
            crv: 'P-256',
            x: 'test-x',
            y: 'test-y',
          })
          .build()
      )
      .build()

    const lote = createLoTE(minimalSchemeInfo, [entity])

    expect(lote.LoTE.TrustedEntitiesList).toHaveLength(1)
    expect(lote.LoTE.TrustedEntitiesList?.[0].TrustedEntityInformation.TEName[0].value).toBe('Test Entity')
  })
})

describe('LoTE Version Management', () => {
  it('should increment sequence number', () => {
    const lote = createLoTE({
      SchemeOperatorName: [{ lang: 'en', value: 'Test' }],
      LoTESequenceNumber: 5,
    })

    const updated = updateLoTEVersion(lote)

    expect(updated.LoTE.ListAndSchemeInformation.LoTESequenceNumber).toBe(6)
  })

  it('should update timestamps when incrementing version', () => {
    const oldDate = '2020-01-01T00:00:00.000Z'
    const lote = createLoTE({
      SchemeOperatorName: [{ lang: 'en', value: 'Test' }],
      ListIssueDateTime: oldDate,
      NextUpdate: oldDate,
    })

    const updated = updateLoTEVersion(lote)

    expect(updated.LoTE.ListAndSchemeInformation.ListIssueDateTime).not.toBe(oldDate)
    expect(updated.LoTE.ListAndSchemeInformation.NextUpdate).not.toBe(oldDate)
  })

  it('should preserve other fields when updating version', () => {
    const lote = createLoTE({
      SchemeOperatorName: [{ lang: 'en', value: 'Test' }],
      SchemeName: [{ lang: 'en', value: 'My Scheme' }],
      SchemeTerritory: 'DE',
    })

    const updated = updateLoTEVersion(lote)

    expect(updated.LoTE.ListAndSchemeInformation.SchemeName).toEqual([{ lang: 'en', value: 'My Scheme' }])
    expect(updated.LoTE.ListAndSchemeInformation.SchemeTerritory).toBe('DE')
  })

  it('should accept custom listIssueDateTime and nextUpdate', () => {
    const lote = createLoTE({
      SchemeOperatorName: [{ lang: 'en', value: 'Test' }],
    })

    const customIssueDate = new Date('2025-06-01T00:00:00.000Z')
    const customNextUpdate = new Date('2025-12-01T00:00:00.000Z')

    const updated = updateLoTEVersion(lote, {
      listIssueDateTime: customIssueDate,
      nextUpdate: customNextUpdate,
    })

    expect(updated.LoTE.ListAndSchemeInformation.ListIssueDateTime).toBe('2025-06-01T00:00:00.000Z')
    expect(updated.LoTE.ListAndSchemeInformation.NextUpdate).toBe('2025-12-01T00:00:00.000Z')
  })

  it('should accept string dates for listIssueDateTime and nextUpdate', () => {
    const lote = createLoTE({
      SchemeOperatorName: [{ lang: 'en', value: 'Test' }],
    })

    const updated = updateLoTEVersion(lote, {
      listIssueDateTime: '2025-06-01T00:00:00.000Z',
      nextUpdate: '2025-12-01T00:00:00.000Z',
    })

    expect(updated.LoTE.ListAndSchemeInformation.ListIssueDateTime).toBe('2025-06-01T00:00:00.000Z')
    expect(updated.LoTE.ListAndSchemeInformation.NextUpdate).toBe('2025-12-01T00:00:00.000Z')
  })

  it('should default NextUpdate to 6 months from listIssueDateTime', () => {
    const lote = createLoTE({
      SchemeOperatorName: [{ lang: 'en', value: 'Test' }],
    })

    const customIssueDate = new Date('2025-01-15T12:00:00.000Z')

    const updated = updateLoTEVersion(lote, {
      listIssueDateTime: customIssueDate,
    })

    const nextUpdate = new Date(updated.LoTE.ListAndSchemeInformation.NextUpdate)
    const issueDate = new Date(updated.LoTE.ListAndSchemeInformation.ListIssueDateTime)

    // NextUpdate should be approximately 6 months after issue date
    const monthsDiff =
      (nextUpdate.getFullYear() - issueDate.getFullYear()) * 12 + (nextUpdate.getMonth() - issueDate.getMonth())
    expect(monthsDiff).toBe(6)
  })
})

describe('LoTE Entity Management', () => {
  const createTestEntity = (name: string): TrustedEntity =>
    trustedEntity()
      .name(name)
      .postalAddress({
        StreetAddress: '123 St',
        Locality: 'City',
        PostalCode: '12345',
        Country: 'DE',
      })
      .email('test@example.com')
      .addService(service().name('Service').addPublicKey({ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }).build())
      .build()

  it('should add a trusted entity', () => {
    let lote = createLoTE({
      SchemeOperatorName: [{ lang: 'en', value: 'Test' }],
    })

    const entity = createTestEntity('New Entity')
    lote = addTrustedEntity(lote, entity)

    expect(lote.LoTE.TrustedEntitiesList).toHaveLength(1)
    expect(lote.LoTE.TrustedEntitiesList?.[0].TrustedEntityInformation.TEName[0].value).toBe('New Entity')
  })

  it('should add multiple entities', () => {
    let lote = createLoTE({
      SchemeOperatorName: [{ lang: 'en', value: 'Test' }],
    })

    lote = addTrustedEntity(lote, createTestEntity('Entity 1'))
    lote = addTrustedEntity(lote, createTestEntity('Entity 2'))
    lote = addTrustedEntity(lote, createTestEntity('Entity 3'))

    expect(lote.LoTE.TrustedEntitiesList).toHaveLength(3)
  })

  it('should remove a trusted entity by name', () => {
    let lote = createLoTE({
      SchemeOperatorName: [{ lang: 'en', value: 'Test' }],
    })

    lote = addTrustedEntity(lote, createTestEntity('Entity A'))
    lote = addTrustedEntity(lote, createTestEntity('Entity B'))
    lote = addTrustedEntity(lote, createTestEntity('Entity C'))

    lote = removeTrustedEntity(lote, 'Entity B')

    expect(lote.LoTE.TrustedEntitiesList).toHaveLength(2)
    expect(
      lote.LoTE.TrustedEntitiesList?.find((e) => e.TrustedEntityInformation.TEName[0].value === 'Entity B')
    ).toBeUndefined()
  })

  it('should add a trusted entity to a list without TrustedEntitiesList', () => {
    const { LoTE } = createLoTE({ SchemeOperatorName: [{ lang: 'en', value: 'Test' }] })
    const { TrustedEntitiesList: _, ...withoutEntities } = LoTE

    const lote = addTrustedEntity({ LoTE: withoutEntities }, createTestEntity('New Entity'))

    expect(lote.LoTE.TrustedEntitiesList).toHaveLength(1)
  })

  it('should leave a list without TrustedEntitiesList as is when removing an entity', () => {
    const { LoTE } = createLoTE({ SchemeOperatorName: [{ lang: 'en', value: 'Test' }] })
    const { TrustedEntitiesList: _, ...withoutEntities } = LoTE

    const lote = removeTrustedEntity({ LoTE: withoutEntities }, 'Entity A')

    expect(lote.LoTE.TrustedEntitiesList).toBeUndefined()
  })

  it('should not modify list when removing non-existent entity', () => {
    let lote = createLoTE({
      SchemeOperatorName: [{ lang: 'en', value: 'Test' }],
    })

    lote = addTrustedEntity(lote, createTestEntity('Entity A'))
    const originalLength = lote.LoTE.TrustedEntitiesList?.length ?? 0

    lote = removeTrustedEntity(lote, 'Non-existent')

    expect(lote.LoTE.TrustedEntitiesList).toHaveLength(originalLength)
  })
})
