import { describe, expect, it } from 'vitest'
import { service, trustedEntity } from '../index'
import type { ServiceHistoryInstance } from '../types'

describe('ServiceBuilder', () => {
  it('should create a minimal service with name and digital identity', () => {
    const svc = service()
      .name('Test Service')
      .addPublicKey({ kty: 'EC', crv: 'P-256', x: 'test-x', y: 'test-y' })
      .build()

    expect(svc.ServiceInformation.ServiceName).toHaveLength(1)
    expect(svc.ServiceInformation.ServiceName[0].value).toBe('Test Service')
    expect(svc.ServiceInformation.ServiceDigitalIdentity.PublicKeyValues).toHaveLength(1)
  })

  it('should support multilingual service names', () => {
    const svc = service()
      .name('Test Service', 'en')
      .name('Test-Dienst', 'de')
      .name('Service de test', 'fr')
      .addPublicKey({ kty: 'EC' })
      .build()

    expect(svc.ServiceInformation.ServiceName).toHaveLength(3)
    expect(svc.ServiceInformation.ServiceName[0].lang).toBe('en')
    expect(svc.ServiceInformation.ServiceName[1].lang).toBe('de')
    expect(svc.ServiceInformation.ServiceName[2].lang).toBe('fr')
  })

  it('should set service type and status', () => {
    const svc = service()
      .name('Test Service')
      .type('https://example.org/service-type/issuer')
      .status('https://example.org/status/granted')
      .addPublicKey({ kty: 'EC' })
      .build()

    expect(svc.ServiceInformation.ServiceTypeIdentifier).toBe('https://example.org/service-type/issuer')
    expect(svc.ServiceInformation.ServiceStatus).toBe('https://example.org/status/granted')
    expect(svc.ServiceInformation.StatusStartingTime).toBeDefined()
  })

  it('should add X.509 certificates', () => {
    const certBase64 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...'
    const svc = service().name('Test Service').addCertificate(certBase64).build()

    expect(svc.ServiceInformation.ServiceDigitalIdentity.X509Certificates).toHaveLength(1)
    expect(svc.ServiceInformation.ServiceDigitalIdentity.X509Certificates?.[0].val).toBe(certBase64)
    expect(svc.ServiceInformation.ServiceDigitalIdentity.X509Certificates?.[0].encoding).toBe(
      'urn:ietf:params:tls-cert-type:x509'
    )
  })

  it('should add X.509 subject names', () => {
    const subjectName = 'CN=Test CA, O=Test Org, C=DE'
    const svc = service().name('Test Service').addX509SubjectName(subjectName).build()

    expect(svc.ServiceInformation.ServiceDigitalIdentity.X509SubjectNames).toHaveLength(1)
    expect(svc.ServiceInformation.ServiceDigitalIdentity.X509SubjectNames?.[0]).toBe(subjectName)
  })

  it('should add X.509 SKIs', () => {
    const ski = 'base64encodedSKI=='
    const svc = service().name('Test Service').addX509SKI(ski).build()

    expect(svc.ServiceInformation.ServiceDigitalIdentity.X509SKIs).toHaveLength(1)
    expect(svc.ServiceInformation.ServiceDigitalIdentity.X509SKIs?.[0]).toBe(ski)
  })

  it('should add other IDs', () => {
    const otherId = 'urn:example:custom-id:12345'
    const svc = service().name('Test Service').addOtherId(otherId).build()

    expect(svc.ServiceInformation.ServiceDigitalIdentity.OtherIds).toHaveLength(1)
    expect(svc.ServiceInformation.ServiceDigitalIdentity.OtherIds?.[0]).toBe(otherId)
  })

  it('should add service endpoints', () => {
    const svc = service()
      .name('Test Service')
      .addPublicKey({ kty: 'EC' })
      .addEndpoint('https://example.org/type/issuer', 'https://issuer.example.com')
      .addEndpoint('https://example.org/type/verifier', 'https://verifier.example.com')
      .build()

    expect(svc.ServiceInformation.ServiceSupplyPoints).toHaveLength(2)
    expect(svc.ServiceInformation.ServiceSupplyPoints?.[0].uriValue).toBe('https://issuer.example.com')
  })

  it('should add a service endpoint without a ServiceType', () => {
    const svc = service()
      .name('Test Service')
      .addPublicKey({ kty: 'EC' })
      .addEndpoint('https://issuer.example.com')
      .addEndpoint(undefined, 'https://verifier.example.com')
      .addEndpoint('https://example.org/type/issuer', 'https://typed.example.com')
      .build()

    expect(svc.ServiceInformation.ServiceSupplyPoints).toStrictEqual([
      { uriValue: 'https://issuer.example.com' },
      { uriValue: 'https://verifier.example.com' },
      { ServiceType: 'https://example.org/type/issuer', uriValue: 'https://typed.example.com' },
    ])
  })

  it('should add service definition URIs', () => {
    const svc = service()
      .name('Test Service')
      .addPublicKey({ kty: 'EC' })
      .addDefinitionUri('https://example.org/service-definition', 'en')
      .build()

    expect(svc.ServiceInformation.ServiceDefinitionURI).toHaveLength(1)
    expect(svc.ServiceInformation.ServiceDefinitionURI?.[0].uriValue).toBe('https://example.org/service-definition')
  })

  it('should add custom extensions', () => {
    const extension = { customField: 'customValue', nested: { a: 1 } }
    const svc = service().name('Test Service').addPublicKey({ kty: 'EC' }).addExtension(extension).build()

    expect(svc.ServiceInformation.ServiceInformationExtensions).toHaveLength(1)
    expect(svc.ServiceInformation.ServiceInformationExtensions?.[0]).toEqual(extension)
  })

  it('should add service history', () => {
    const historyEntry: ServiceHistoryInstance = {
      ServiceName: [{ lang: 'en', value: 'Old Service Name' }],
      ServiceDigitalIdentity: { PublicKeyValues: [{ kty: 'EC' }] },
      ServiceStatus: 'https://example.org/status/revoked',
      StatusStartingTime: '2023-01-01T00:00:00.000Z',
    }

    const svc = service().name('Current Service Name').addPublicKey({ kty: 'EC' }).addHistoryEntry(historyEntry).build()

    expect(svc.ServiceHistory).toHaveLength(1)
    expect(svc.ServiceHistory?.[0].ServiceName[0].value).toBe('Old Service Name')
    expect(svc.ServiceHistory?.[0].ServiceStatus).toBe('https://example.org/status/revoked')
  })

  it('should throw when service name is missing', () => {
    expect(() => {
      service().addPublicKey({ kty: 'EC' }).build()
    }).toThrow('Invalid TrustedEntityService')
  })

  it('should throw when digital identity is missing', () => {
    expect(() => {
      service().name('Test Service').build()
    }).toThrow('Invalid TrustedEntityService')
  })
})

describe('TrustedEntityBuilder', () => {
  it('should create a minimal trusted entity', () => {
    const entity = trustedEntity()
      .name('Test Entity')
      .postalAddress({
        StreetAddress: '123 Test St',
        Locality: 'Test City',
        PostalCode: '12345',
        Country: 'DE',
      })
      .email('test@example.com')
      .addService(service().name('Test Service').addPublicKey({ kty: 'EC' }).build())
      .build()

    expect(entity.TrustedEntityInformation.TEName).toHaveLength(1)
    expect(entity.TrustedEntityInformation.TEName[0].value).toBe('Test Entity')
    expect(entity.TrustedEntityServices).toHaveLength(1)
  })

  it('should support multilingual entity names', () => {
    const entity = trustedEntity()
      .name('Test Entity', 'en')
      .name('Testeinheit', 'de')
      .postalAddress({
        StreetAddress: '123 St',
        Locality: 'City',
        PostalCode: '12345',
        Country: 'DE',
      })
      .email('test@example.com')
      .addService(service().name('Svc').addPublicKey({ kty: 'EC' }).build())
      .build()

    expect(entity.TrustedEntityInformation.TEName).toHaveLength(2)
    expect(entity.TrustedEntityInformation.TEName[0].lang).toBe('en')
    expect(entity.TrustedEntityInformation.TEName[1].lang).toBe('de')
  })

  it('should set trade name', () => {
    const entity = trustedEntity()
      .name('Acme Corp')
      .tradeName('Acme')
      .tradeName('ACME Inc', 'en')
      .postalAddress({
        StreetAddress: '123 St',
        Locality: 'City',
        PostalCode: '12345',
        Country: 'DE',
      })
      .email('test@acme.com')
      .addService(service().name('Svc').addPublicKey({ kty: 'EC' }).build())
      .build()

    expect(entity.TrustedEntityInformation.TETradeName).toHaveLength(2)
    expect(entity.TrustedEntityInformation.TETradeName?.[0].value).toBe('Acme')
  })

  it('should add multiple postal addresses', () => {
    const entity = trustedEntity()
      .name('Test Entity')
      .postalAddress({
        StreetAddress: '123 Main St',
        Locality: 'Berlin',
        PostalCode: '10115',
        Country: 'DE',
      })
      .postalAddress(
        {
          StreetAddress: '456 Oak Ave',
          Locality: 'New York',
          PostalCode: '10001',
          Country: 'US',
        },
        'en'
      )
      .email('test@example.com')
      .addService(service().name('Svc').addPublicKey({ kty: 'EC' }).build())
      .build()

    expect(entity.TrustedEntityInformation.TEAddress.TEPostalAddress).toHaveLength(2)
  })

  it('should add email with mailto prefix', () => {
    const entity = trustedEntity()
      .name('Test Entity')
      .postalAddress({
        StreetAddress: '123 St',
        Locality: 'City',
        PostalCode: '12345',
        Country: 'DE',
      })
      .email('test@example.com')
      .addService(service().name('Svc').addPublicKey({ kty: 'EC' }).build())
      .build()

    expect(entity.TrustedEntityInformation.TEAddress.TEElectronicAddress[0].uriValue).toBe('mailto:test@example.com')
  })

  it('should not duplicate mailto prefix', () => {
    const entity = trustedEntity()
      .name('Test Entity')
      .postalAddress({
        StreetAddress: '123 St',
        Locality: 'City',
        PostalCode: '12345',
        Country: 'DE',
      })
      .email('mailto:test@example.com')
      .addService(service().name('Svc').addPublicKey({ kty: 'EC' }).build())
      .build()

    expect(entity.TrustedEntityInformation.TEAddress.TEElectronicAddress[0].uriValue).toBe('mailto:test@example.com')
  })

  it('should add website URLs', () => {
    const entity = trustedEntity()
      .name('Test Entity')
      .postalAddress({
        StreetAddress: '123 St',
        Locality: 'City',
        PostalCode: '12345',
        Country: 'DE',
      })
      .website('https://example.com')
      .addService(service().name('Svc').addPublicKey({ kty: 'EC' }).build())
      .build()

    expect(entity.TrustedEntityInformation.TEAddress.TEElectronicAddress[0].uriValue).toBe('https://example.com')
  })

  it('should add https prefix to website if missing', () => {
    const entity = trustedEntity()
      .name('Test Entity')
      .postalAddress({
        StreetAddress: '123 St',
        Locality: 'City',
        PostalCode: '12345',
        Country: 'DE',
      })
      .website('example.com')
      .addService(service().name('Svc').addPublicKey({ kty: 'EC' }).build())
      .build()

    expect(entity.TrustedEntityInformation.TEAddress.TEElectronicAddress[0].uriValue).toBe('https://example.com')
  })

  it('should add information URIs', () => {
    const entity = trustedEntity()
      .name('Test Entity')
      .postalAddress({
        StreetAddress: '123 St',
        Locality: 'City',
        PostalCode: '12345',
        Country: 'DE',
      })
      .email('test@example.com')
      .infoUri('https://example.com/info')
      .infoUri('https://example.com/terms', 'en')
      .addService(service().name('Svc').addPublicKey({ kty: 'EC' }).build())
      .build()

    expect(entity.TrustedEntityInformation.TEInformationURI).toHaveLength(2)
  })

  it('should add custom extensions', () => {
    const extension = { customData: { value: 123 } }
    const entity = trustedEntity()
      .name('Test Entity')
      .postalAddress({
        StreetAddress: '123 St',
        Locality: 'City',
        PostalCode: '12345',
        Country: 'DE',
      })
      .email('test@example.com')
      .addExtension(extension)
      .addService(service().name('Svc').addPublicKey({ kty: 'EC' }).build())
      .build()

    expect(entity.TrustedEntityInformation.TEInformationExtensions).toHaveLength(1)
    expect(entity.TrustedEntityInformation.TEInformationExtensions?.[0]).toEqual(extension)
  })

  it('should add multiple services', () => {
    const entity = trustedEntity()
      .name('Test Entity')
      .postalAddress({
        StreetAddress: '123 St',
        Locality: 'City',
        PostalCode: '12345',
        Country: 'DE',
      })
      .email('test@example.com')
      .addService(service().name('Service 1').addPublicKey({ kty: 'EC' }).build())
      .addService(service().name('Service 2').addPublicKey({ kty: 'RSA' }).build())
      .addService(service().name('Service 3').addCertificate('base64cert').build())
      .build()

    expect(entity.TrustedEntityServices).toHaveLength(3)
  })

  it('should throw when entity name is missing', () => {
    expect(() => {
      trustedEntity()
        .postalAddress({
          StreetAddress: '123 St',
          Locality: 'City',
          PostalCode: '12345',
          Country: 'DE',
        })
        .email('test@example.com')
        .addService(service().name('Svc').addPublicKey({ kty: 'EC' }).build())
        .build()
    }).toThrow('Invalid TrustedEntity')
  })

  it('should throw when address is missing', () => {
    expect(() => {
      trustedEntity()
        .name('Test Entity')
        .addService(service().name('Svc').addPublicKey({ kty: 'EC' }).build())
        .build()
    }).toThrow('Invalid TrustedEntity')
  })
})
