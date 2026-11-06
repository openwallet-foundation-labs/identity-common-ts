import { describe, expect, it } from 'vitest'
import {
  createLegalPersonRegistrationCertificate,
  createNaturalPersonRegistrationCertificate,
  createRegistrationCertificatePayload,
  credential,
  hasAttestationProviderEntitlement,
  isLegalPersonRegistrationCertificate,
  isNaturalPersonRegistrationCertificate,
  isPspSubEntitlement,
  isValidEntitlement,
  PSP_SUB_ENTITLEMENTS,
  RegistrationCertificateValidationError,
  registrationCertificate,
  validateLegalPersonRegistrationCertificate,
  validateNaturalPersonRegistrationCertificate,
  validateRegistrationCertificate,
  validateRegistrationCertificateJwtHeader,
  validateRegistrationCertificatePayload,
  WRP_ENTITLEMENTS,
  zRegistrationCertificatePayload,
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

describe('zRegistrationCertificatePayload', () => {
  it('should validate a legal person payload', () => {
    const result = zRegistrationCertificatePayload.safeParse(validLegalPersonPayload)
    expect(result.success).toBe(true)
  })

  it('should validate a natural person payload', () => {
    const result = zRegistrationCertificatePayload.safeParse(validNaturalPersonPayload)
    expect(result.success).toBe(true)
  })

  it('should reject payload without required fields', () => {
    const result = zRegistrationCertificatePayload.safeParse({})
    expect(result.success).toBe(false)
  })

  it('should reject payload with empty entitlements', () => {
    const payload = { ...validLegalPersonPayload, entitlements: [] }
    const result = zRegistrationCertificatePayload.safeParse(payload)
    expect(result.success).toBe(false)
  })

  it('should reject payload with invalid country code', () => {
    const payload = { ...validLegalPersonPayload, country: 'GERMANY' }
    const result = zRegistrationCertificatePayload.safeParse(payload)
    expect(result.success).toBe(false)
  })

  it('should accept payload with optional fields', () => {
    const payload = {
      ...validLegalPersonPayload,
      privacy_policy: 'https://example.com/privacy',
      info_uri: 'https://example.com',
      support_uri: 'https://example.com/support',
    }
    const result = zRegistrationCertificatePayload.safeParse(payload)
    expect(result.success).toBe(true)
  })

  it('should accept a payload with a jti', () => {
    const jti_uuid = '0c1f7a2e-3d4b-4c5a-8e9f-1a2b3c4d5e6f'
    const payload = { ...validLegalPersonPayload, jti: jti_uuid }
    const result = zRegistrationCertificatePayload.safeParse(payload)

    expect(result.success).toBe(true)
    expect(result.data?.jti).toBe(jti_uuid)
  })

  it('should accept a payload without a jti', () => {
    const result = zRegistrationCertificatePayload.safeParse(validLegalPersonPayload)

    expect(result.success).toBe(true)
    expect(result.data?.jti).toBeUndefined()
  })

  it('should reject an empty jti', () => {
    const payload = { ...validLegalPersonPayload, jti: '' }
    const result = zRegistrationCertificatePayload.safeParse(payload)
    expect(result.success).toBe(false)
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

  describe('isPspSubEntitlement', () => {
    it('should return true for PSP sub-entitlements', () => {
      expect(isPspSubEntitlement(PSP_SUB_ENTITLEMENTS.PAYMENT_INITIATION)).toBe(true)
    })

    it('should return false for non-PSP entitlements', () => {
      expect(isPspSubEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)).toBe(false)
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
  describe('validateRegistrationCertificatePayload', () => {
    it('should validate valid payload', () => {
      const result = validateRegistrationCertificatePayload(validLegalPersonPayload, validLegalPersonPayload.sub)
      expect(result.valid).toBe(true)
      expect(result.issues.filter((issue) => issue.severity === 'error')).toHaveLength(0)
    })

    it('should return errors for invalid payload', () => {
      const result = validateRegistrationCertificatePayload({}, 'LEIXG-529900T8BM49AURSDO55')
      expect(result.valid).toBe(false)
      expect(result.issues.some((issue) => issue.severity === 'error')).toBe(true)
    })

    it('should warn about unknown entitlements', () => {
      const payload = {
        ...validLegalPersonPayload,
        entitlements: ['https://custom.example.com/entitlement'],
      }
      const result = validateRegistrationCertificatePayload(payload, payload.sub)
      expect(result.issues.some((issue) => issue.severity === 'warning' && issue.code === 'unknown_entitlement')).toBe(
        true
      )
    })

    it('should error when PSP sub-entitlement without Service_Provider', () => {
      const payload = {
        ...validLegalPersonPayload,
        entitlements: [PSP_SUB_ENTITLEMENTS.PAYMENT_INITIATION],
      }
      const result = validateRegistrationCertificatePayload(payload, payload.sub)
      expect(result.valid).toBe(false)
      expect(
        result.issues.some((issue) => issue.severity === 'error' && issue.code === 'missing_base_entitlement')
      ).toBe(true)
    })

    it('should allow PSP sub-entitlement with Service_Provider', () => {
      const payload = {
        ...validLegalPersonPayload,
        entitlements: [WRP_ENTITLEMENTS.SERVICE_PROVIDER, PSP_SUB_ENTITLEMENTS.PAYMENT_INITIATION],
      }
      const result = validateRegistrationCertificatePayload(payload, payload.sub)
      expect(
        result.issues.some((issue) => issue.severity === 'error' && issue.code === 'missing_base_entitlement')
      ).toBe(false)
    })
  })

  describe('validateRegistrationCertificateJwtHeader', () => {
    it('should validate valid header', () => {
      const result = validateRegistrationCertificateJwtHeader(validJWTHeader)
      expect(result.valid).toBe(true)
    })

    it('should reject invalid typ', () => {
      const result = validateRegistrationCertificateJwtHeader({ ...validJWTHeader, typ: 'jwt' })
      expect(result.valid).toBe(false)
    })
  })

  describe('validateRegistrationCertificate', () => {
    it('should validate complete registration certificate', () => {
      const result = validateRegistrationCertificate(
        validJWTHeader,
        validLegalPersonPayload,
        validLegalPersonPayload.sub
      )
      expect(result.valid).toBe(true)
    })
  })

  describe('isLegalPersonRegistrationCertificate', () => {
    it('should return true for legal person', () => {
      expect(isLegalPersonRegistrationCertificate(validLegalPersonPayload)).toBe(true)
    })

    it('should return false for natural person', () => {
      expect(isLegalPersonRegistrationCertificate(validNaturalPersonPayload)).toBe(false)
    })
  })

  describe('isNaturalPersonRegistrationCertificate', () => {
    it('should return true for natural person', () => {
      expect(isNaturalPersonRegistrationCertificate(validNaturalPersonPayload)).toBe(true)
    })

    it('should return false for legal person', () => {
      expect(isNaturalPersonRegistrationCertificate(validLegalPersonPayload)).toBe(false)
    })
  })

  describe('validateLegalPersonRegistrationCertificate', () => {
    it('should validate legal person payload', () => {
      const result = validateLegalPersonRegistrationCertificate(validLegalPersonPayload)
      expect(result.valid).toBe(true)
    })
  })

  describe('validateNaturalPersonRegistrationCertificate', () => {
    it('should validate natural person payload', () => {
      const result = validateNaturalPersonRegistrationCertificate(validNaturalPersonPayload)
      expect(result.valid).toBe(true)
    })
  })
})

// ============================================================================
// Builder Tests
// ============================================================================

describe('RegistrationCertificateBuilder', () => {
  it('should build a legal person payload', () => {
    const payload = registrationCertificate()
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
    const payload = registrationCertificate()
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

  it('should omit jti when no certificate id is set', () => {
    const payload = registrationCertificate()
      .name('Test Service')
      .legalName('Test Inc.')
      .identifier('LEIXG-529900T8BM49AURSDO55')
      .country('DE')
      .registryUri('https://registry.example.com/api')
      .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
      .build()

    expect(payload.jti).toBeUndefined()
  })

  it('should preserve an explicitly set certificate id', () => {
    const jti_uuid = 'urn:uuid:0c1f7a2e-3d4b-4c5a-8e9f-1a2b3c4d5e6f'
    const payload = registrationCertificate()
      .name('Test Service')
      .legalName('Test Inc.')
      .identifier('LEIXG-529900T8BM49AURSDO55')
      .country('DE')
      .registryUri('https://registry.example.com/api')
      .addEntitlement(WRP_ENTITLEMENTS.SERVICE_PROVIDER)
      .certificateId(jti_uuid)
      .build()

    expect(payload.jti).toBe(jti_uuid)
  })

  it('should add multiple entitlements', () => {
    const payload = registrationCertificate()
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
    const payload = registrationCertificate()
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
    const payload = registrationCertificate()
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
    const payload = registrationCertificate()
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
      registrationCertificate().name('Test').build()
    }).toThrow(RegistrationCertificateValidationError)
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
  describe('createLegalPersonRegistrationCertificate', () => {
    it('should create a legal person registration certificate', () => {
      const payload = createLegalPersonRegistrationCertificate({
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

  describe('createNaturalPersonRegistrationCertificate', () => {
    it('should create a natural person registration certificate', () => {
      const payload = createNaturalPersonRegistrationCertificate({
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

  describe('createRegistrationCertificatePayload', () => {
    it('should carry a provided jti through', () => {
      const jti_uuid = 'urn:uuid:0c1f7a2e-3d4b-4c5a-8e9f-1a2b3c4d5e6f'
      const payload = createRegistrationCertificatePayload(
        {
          ...validLegalPersonPayload,
          jti: jti_uuid,
        },
        validLegalPersonPayload.sub
      )

      expect(payload.jti).toBe(jti_uuid)
    })
  })
})

// ============================================================================
// Error Tests
// ============================================================================

describe('RegistrationCertificateValidationError', () => {
  it('should create an error with message and issues', () => {
    const issues = [{ severity: 'error' as const, code: 'invalid_signature' as const, path: [], message: 'Invalid' }]
    const error = new RegistrationCertificateValidationError('Test error', issues)
    expect(error.message).toBe('Test error\n  - Invalid (invalid_signature)')
    expect(error.name).toBe('RegistrationCertificateValidationError')
    expect(error.issues).toBe(issues)
    expect(error).toBeInstanceOf(Error)
  })
})
