import { describe, expect, it } from 'vitest'
import {
  createLegalPersonWRPRC,
  createNaturalPersonWRPRC,
  credential,
  getWRPRCPayloadJSONSchema,
  getWRPRCPayloadJSONSchemaString,
  hasAttestationProviderEntitlement,
  isLegalPersonWRPRC,
  isNaturalPersonWRPRC,
  isPSPSubEntitlement,
  isValidEntitlement,
  PSP_SUB_ENTITLEMENTS,
  validateLegalPersonWRPRC,
  validateNaturalPersonWRPRC,
  validateWRPRC,
  validateWRPRCJWTHeader,
  validateWRPRCPayload,
  WRP_ENTITLEMENTS,
  WRPRCException,
  WRPRCPayloadSchema,
  wrprc,
} from '../index'

// ============================================================================
// Test Fixtures
// ============================================================================

const validLegalPersonPayload = {
  name: 'Test Service Provider',
  sub_ln: 'Test Legal Name Inc.',
  sub: 'LEIXG-529900T8BM49AURSDO55',
  country: 'DE',
  registry_uri: 'https://registry.example.com/api',
  entitlements: [WRP_ENTITLEMENTS.SERVICE_PROVIDER],
  iat: Math.floor(Date.now() / 1000),
}

const validNaturalPersonPayload = {
  name: 'Self-Employed Consultant',
  sub_gn: 'Maria',
  sub_fn: 'Rossi',
  sub: 'TINIT-RSSMRA85T10A562S',
  country: 'IT',
  registry_uri: 'https://registry.example.it/api',
  entitlements: [WRP_ENTITLEMENTS.SERVICE_PROVIDER],
  iat: Math.floor(Date.now() / 1000),
}

const validJWTHeader = {
  typ: 'rc-wrp+jwt' as const,
  alg: 'ES256' as const,
  x5c: ['MIIBkDCB...'],
  iat: Math.floor(Date.now() / 1000),
}

// ============================================================================
// Schema Tests
// ============================================================================

describe('WRPRCPayloadSchema', () => {
  it('should validate a legal person payload', () => {
    const result = WRPRCPayloadSchema.safeParse(validLegalPersonPayload)
    expect(result.success).toBe(true)
  })

  it('should validate a natural person payload', () => {
    const result = WRPRCPayloadSchema.safeParse(validNaturalPersonPayload)
    expect(result.success).toBe(true)
  })

  it('should reject payload without required fields', () => {
    const result = WRPRCPayloadSchema.safeParse({})
    expect(result.success).toBe(false)
  })

  it('should reject payload with empty entitlements', () => {
    const payload = { ...validLegalPersonPayload, entitlements: [] }
    const result = WRPRCPayloadSchema.safeParse(payload)
    expect(result.success).toBe(false)
  })

  it('should reject payload with invalid country code', () => {
    const payload = { ...validLegalPersonPayload, country: 'GERMANY' }
    const result = WRPRCPayloadSchema.safeParse(payload)
    expect(result.success).toBe(false)
  })

  it('should accept payload with optional fields', () => {
    const payload = {
      ...validLegalPersonPayload,
      privacy_policy: 'https://example.com/privacy',
      info_uri: 'https://example.com',
      support_uri: 'https://example.com/support',
    }
    const result = WRPRCPayloadSchema.safeParse(payload)
    expect(result.success).toBe(true)
  })

  it('should generate JSON Schema from WRPRCPayloadSchema', () => {
    const jsonSchema = getWRPRCPayloadJSONSchema()
    expect(jsonSchema).toBeTypeOf('object')
    expect(jsonSchema).toHaveProperty('type', 'object')
    expect(jsonSchema).toHaveProperty('properties')
  })

  it('should generate JSON Schema string from WRPRCPayloadSchema', () => {
    const jsonSchemaString = getWRPRCPayloadJSONSchemaString()
    const parsed = JSON.parse(jsonSchemaString)
    expect(parsed).toHaveProperty('type', 'object')
    expect(parsed).toHaveProperty('properties')
  })
})

// ============================================================================
// Entitlement Tests
// ============================================================================

describe('Entitlements', () => {
  it('should have valid entitlement URIs', () => {
    expect(WRP_ENTITLEMENTS.SERVICE_PROVIDER).toBe('https://uri.etsi.org/19475/Entitlement/Service_Provider')
    expect(WRP_ENTITLEMENTS.QEAA_PROVIDER).toBe('https://uri.etsi.org/19475/Entitlement/QEAA_Provider')
    expect(WRP_ENTITLEMENTS.PID_PROVIDER).toBe('https://uri.etsi.org/19475/Entitlement/PID_Provider')
  })

  it('should have PSP sub-entitlements', () => {
    expect(PSP_SUB_ENTITLEMENTS.PAYMENT_INITIATION).toBe('https://uri.etsi.org/19475/SubEntitlement/psp/psp-pi')
    expect(PSP_SUB_ENTITLEMENTS.ACCOUNT_INFORMATION).toBe('https://uri.etsi.org/19475/SubEntitlement/psp/psp-ai')
  })

  describe('isValidEntitlement', () => {
    it('should return true for valid entitlements', () => {
      expect(isValidEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)).toBe(true)
      expect(isValidEntitlement(WRP_ENTITLEMENTS.QEAA_PROVIDER)).toBe(true)
    })

    it('should return false for invalid entitlements', () => {
      expect(isValidEntitlement('invalid-entitlement')).toBe(false)
    })
  })

  describe('isPSPSubEntitlement', () => {
    it('should return true for PSP sub-entitlements', () => {
      expect(isPSPSubEntitlement(PSP_SUB_ENTITLEMENTS.PAYMENT_INITIATION)).toBe(true)
    })

    it('should return false for non-PSP entitlements', () => {
      expect(isPSPSubEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)).toBe(false)
    })
  })

  describe('hasAttestationProviderEntitlement', () => {
    it('should return true for attestation provider entitlements', () => {
      expect(hasAttestationProviderEntitlement([WRP_ENTITLEMENTS.QEAA_PROVIDER])).toBe(true)
      expect(hasAttestationProviderEntitlement([WRP_ENTITLEMENTS.PID_PROVIDER])).toBe(true)
    })

    it('should return false for service provider only', () => {
      expect(hasAttestationProviderEntitlement([WRP_ENTITLEMENTS.SERVICE_PROVIDER])).toBe(false)
    })
  })
})

// ============================================================================
// Validator Tests
// ============================================================================

describe('Validators', () => {
  describe('validateWRPRCPayload', () => {
    it('should validate valid payload', () => {
      const result = validateWRPRCPayload(validLegalPersonPayload)
      expect(result.valid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    it('should return errors for invalid payload', () => {
      const result = validateWRPRCPayload({})
      expect(result.valid).toBe(false)
      expect(result.errors.length).toBeGreaterThan(0)
    })

    it('should warn about unknown entitlements', () => {
      const payload = {
        ...validLegalPersonPayload,
        entitlements: ['https://custom.example.com/entitlement'],
      }
      const result = validateWRPRCPayload(payload)
      expect(result.warnings.some((w) => w.code === 'unknown_entitlement')).toBe(true)
    })

    it('should error when PSP sub-entitlement without Service_Provider', () => {
      const payload = {
        ...validLegalPersonPayload,
        entitlements: [PSP_SUB_ENTITLEMENTS.PAYMENT_INITIATION],
      }
      const result = validateWRPRCPayload(payload)
      expect(result.valid).toBe(false)
      expect(result.errors.some((e) => e.code === 'missing_base_entitlement')).toBe(true)
    })

    it('should allow PSP sub-entitlement with Service_Provider', () => {
      const payload = {
        ...validLegalPersonPayload,
        entitlements: [WRP_ENTITLEMENTS.SERVICE_PROVIDER, PSP_SUB_ENTITLEMENTS.PAYMENT_INITIATION],
      }
      const result = validateWRPRCPayload(payload)
      expect(result.errors.some((e) => e.code === 'missing_base_entitlement')).toBe(false)
    })
  })

  describe('validateWRPRCJWTHeader', () => {
    it('should validate valid header', () => {
      const result = validateWRPRCJWTHeader(validJWTHeader)
      expect(result.valid).toBe(true)
    })

    it('should reject invalid typ', () => {
      const result = validateWRPRCJWTHeader({ ...validJWTHeader, typ: 'jwt' })
      expect(result.valid).toBe(false)
    })
  })

  describe('validateWRPRC', () => {
    it('should validate complete WRPRC', () => {
      const result = validateWRPRC(validJWTHeader, validLegalPersonPayload)
      expect(result.valid).toBe(true)
    })
  })

  describe('isLegalPersonWRPRC', () => {
    it('should return true for legal person', () => {
      expect(isLegalPersonWRPRC(validLegalPersonPayload)).toBe(true)
    })

    it('should return false for natural person', () => {
      expect(isLegalPersonWRPRC(validNaturalPersonPayload)).toBe(false)
    })
  })

  describe('isNaturalPersonWRPRC', () => {
    it('should return true for natural person', () => {
      expect(isNaturalPersonWRPRC(validNaturalPersonPayload)).toBe(true)
    })

    it('should return false for legal person', () => {
      expect(isNaturalPersonWRPRC(validLegalPersonPayload)).toBe(false)
    })
  })

  describe('validateLegalPersonWRPRC', () => {
    it('should validate legal person payload', () => {
      const result = validateLegalPersonWRPRC(validLegalPersonPayload)
      expect(result.valid).toBe(true)
    })
  })

  describe('validateNaturalPersonWRPRC', () => {
    it('should validate natural person payload', () => {
      const result = validateNaturalPersonWRPRC(validNaturalPersonPayload)
      expect(result.valid).toBe(true)
    })
  })
})

// ============================================================================
// Builder Tests
// ============================================================================

describe('WRPRCBuilder', () => {
  it('should build a legal person payload', () => {
    const payload = wrprc()
      .name('Test Service')
      .legalName('Test Inc.')
      .identifier('LEIXG-529900T8BM49AURSDO55')
      .country('DE')
      .registryUri('https://registry.example.com/api')
      .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
      .build()

    expect(payload.name).toBe('Test Service')
    expect(payload.sub_ln).toBe('Test Inc.')
    expect(payload.sub).toBe('LEIXG-529900T8BM49AURSDO55')
    expect(payload.country).toBe('DE')
    expect(payload.entitlements).toContain(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
  })

  it('should build a natural person payload', () => {
    const payload = wrprc()
      .name('Consultant')
      .givenName('Maria')
      .familyName('Rossi')
      .identifier('TINIT-RSSMRA85T10A562S')
      .country('IT')
      .registryUri('https://registry.example.it/api')
      .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
      .build()

    expect(payload.sub_gn).toBe('Maria')
    expect(payload.sub_fn).toBe('Rossi')
  })

  it('should add multiple entitlements', () => {
    const payload = wrprc()
      .name('Test')
      .legalName('Test Inc.')
      .identifier('LEIXG-123')
      .country('NL')
      .registryUri('https://example.com/api')
      .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
      .addEntitlement(WRP_ENTITLEMENTS.QEAA_PROVIDER)
      .build()

    expect(payload.entitlements).toContain(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
    expect(payload.entitlements).toContain(WRP_ENTITLEMENTS.QEAA_PROVIDER)
  })

  it('should not duplicate entitlements', () => {
    const payload = wrprc()
      .name('Test')
      .legalName('Test Inc.')
      .identifier('LEIXG-123')
      .country('NL')
      .registryUri('https://example.com/api')
      .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
      .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
      .build()

    const count = payload.entitlements.filter((e) => e === WRP_ENTITLEMENTS.SERVICE_PROVIDER).length
    expect(count).toBe(1)
  })

  it('should add optional fields', () => {
    const payload = wrprc()
      .name('Test')
      .legalName('Test Inc.')
      .identifier('LEIXG-123')
      .country('NL')
      .registryUri('https://example.com/api')
      .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
      .privacyPolicy('https://example.com/privacy')
      .infoUri('https://example.com')
      .supportUri('https://example.com/support')
      .build()

    expect(payload.privacy_policy).toBe('https://example.com/privacy')
    expect(payload.info_uri).toBe('https://example.com')
    expect(payload.support_uri).toBe('https://example.com/support')
  })

  it('should add credentials', () => {
    const payload = wrprc()
      .name('Test')
      .legalName('Test Inc.')
      .identifier('LEIXG-123')
      .country('NL')
      .registryUri('https://example.com/api')
      .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
      .addCredential({
        format: 'dc+sd-jwt',
        meta: { vct: 'https://example.com/vct' },
      })
      .build()

    expect(payload.credentials).toHaveLength(1)
    expect(payload.credentials?.[0].format).toBe('dc+sd-jwt')
  })

  it('should throw on invalid payload', () => {
    expect(() => {
      wrprc().name('Test').build()
    }).toThrow(WRPRCException)
  })
})

describe('CredentialBuilder', () => {
  it('should build a credential', () => {
    const cred = credential()
      .format('dc+sd-jwt')
      .meta({ vct: 'https://example.com/vct' })
      .addPathClaim('given_name')
      .addPathClaim('family_name')
      .build()

    expect(cred.format).toBe('dc+sd-jwt')
    expect(cred.meta).toEqual({ vct: 'https://example.com/vct' })
    expect(cred.claim).toHaveLength(2)
  })

  it('should add claim with values', () => {
    const cred = credential()
      .format('mso_mdoc')
      .meta({ doctype: 'org.iso.18013.5.1.mDL' })
      .addClaim({ path: ['age_over_18'], values: [true] })
      .build()

    expect(cred.claim?.[0].values).toEqual([true])
  })
})

// ============================================================================
// Factory Function Tests
// ============================================================================

describe('Factory Functions', () => {
  describe('createLegalPersonWRPRC', () => {
    it('should create a legal person WRPRC', () => {
      const payload = createLegalPersonWRPRC({
        name: 'Test Service',
        legalName: 'Test Inc.',
        identifier: 'LEIXG-123',
        country: 'DE',
        registryUri: 'https://example.com/api',
        entitlements: [WRP_ENTITLEMENTS.SERVICE_PROVIDER],
      })

      expect(payload.name).toBe('Test Service')
      expect(payload.sub_ln).toBe('Test Inc.')
    })
  })

  describe('createNaturalPersonWRPRC', () => {
    it('should create a natural person WRPRC', () => {
      const payload = createNaturalPersonWRPRC({
        name: 'Consultant',
        givenName: 'Maria',
        familyName: 'Rossi',
        identifier: 'TINIT-123',
        country: 'IT',
        registryUri: 'https://example.it/api',
        entitlements: [WRP_ENTITLEMENTS.SERVICE_PROVIDER],
      })

      expect(payload.sub_gn).toBe('Maria')
      expect(payload.sub_fn).toBe('Rossi')
    })
  })
})

// ============================================================================
// Exception Tests
// ============================================================================

describe('WRPRCException', () => {
  it('should create exception with message', () => {
    const error = new WRPRCException('Test error')
    expect(error.message).toBe('Test error')
    expect(error.name).toBe('WRPRCException')
  })

  it('should be instanceof Error', () => {
    const error = new WRPRCException('Test')
    expect(error).toBeInstanceOf(Error)
  })
})
