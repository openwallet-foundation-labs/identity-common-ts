import { describe, expect, it } from 'vitest'

import { constraintSchema } from '../constraints'
import { entityConfigurationClaimsSchema } from '../entityConfiguration'
import { entityStatementClaimsSchema } from '../entityStatement'
import { federationEntityMetadata, openIdProviderEntityMetadata } from '../metadata'
import { metadataPolicySchema } from '../metadata/metadataPolicy'
import { trustMarkClaimsSchema, trustMarkIssuerSchema, trustMarkOwnerSchema } from '../trustMark'
import { validate } from '../utils/validate'
import { constraintsFigure17 } from './fixtures/constraintsFigure17'
import { entityConfigurationFigure8 } from './fixtures/entityConfigurationFigure8'
import { entityConfigurationFigure9 } from './fixtures/entityConfigurationFigure9'
import { entityConfigurationFigure18 } from './fixtures/entityConfigurationFigure18'
import { entityConfigurationFigure43 } from './fixtures/entityConfigurationFigure43'
import { entityConfigurationFigure50 } from './fixtures/entityConfigurationFigure50'
import { entityConfigurationFigure52 } from './fixtures/entityConfigurationFigure52'
import { entityConfigurationFigure56 } from './fixtures/entityConfigurationFigure56'
import { entityConfigurationFigure60 } from './fixtures/entityConfigurationFigure60'
import { entityConfigurationFigure69 } from './fixtures/entityConfigurationFigure69'
import { entityStatementFigure2 } from './fixtures/entityStatementFigure2'
import { entityStatementFigure26 } from './fixtures/entityStatementFigure26'
import { entityStatementFigure54 } from './fixtures/entityStatementFigure54'
import { entityStatementFigure58 } from './fixtures/entityStatementFigure58'
import { entityStatementFigure62 } from './fixtures/entityStatementFigure62'
import { entityStatementFigure70 } from './fixtures/entityStatementFigure70'
import { federationEntityMetadataFigure7 } from './fixtures/federationEntityMetadataFigure7'
import { metadataFigure63 } from './fixtures/metadataFigure63'
import { metadataPolicyFigure12 } from './fixtures/metadataPolicyFigure12'
import { trustMarkClaimsFigure19 } from './fixtures/trustMarkClaimsFigure19'
import { trustMarkClaimsFigure21 } from './fixtures/trustMarkClaimsFigure21'
import { trustMarkClaimsFigure22 } from './fixtures/trustMarkClaimsFigure22'
import { trustMarkClaimsFigure23 } from './fixtures/trustMarkClaimsFigure23'
import { trustMarkClaimsFigure24 } from './fixtures/trustMarkClaimsFigure24'
import { trustMarkIssuersFigure4 } from './fixtures/trustMarkIssuersFigure4'
import { trustMarkOwnersFigure3 } from './fixtures/trustMarkOwnersFigure3'
import { trustMarkClaimsFigure20 } from './fixtures/trustmarkClaimsFigure20'

describe('zod validation schemas', () => {
  describe('validate valid test vectors', () => {
    it('should validate figure 2  -- entity statement', () => {
      expect(() =>
        validate({
          schema: entityStatementClaimsSchema,
          data: entityStatementFigure2,
        })
      ).not.toThrow()
    })

    it('should validate figure 3  -- trust mark owners', () => {
      expect(() => validate({ schema: trustMarkOwnerSchema, data: trustMarkOwnersFigure3 })).not.toThrow()
    })

    it('should validate figure 4  -- trust mark issuers', () => {
      expect(() =>
        validate({
          schema: trustMarkIssuerSchema,
          data: trustMarkIssuersFigure4,
        })
      ).not.toThrow()
    })

    it('should validate figure 7  -- federation entity metadata', () => {
      expect(() =>
        validate({
          schema: federationEntityMetadata.schema,
          data: federationEntityMetadataFigure7,
        })
      ).not.toThrow()
    })

    it('should validate figure 8  -- entity configuration', () => {
      expect(() =>
        validate({
          schema: entityConfigurationClaimsSchema,
          data: entityConfigurationFigure8,
        })
      ).not.toThrow()
    })

    it('should validate figure 9  -- entity configuration', () => {
      expect(() =>
        validate({
          schema: entityConfigurationClaimsSchema,
          data: entityConfigurationFigure9,
        })
      ).not.toThrow()
    })

    it('should validate figure 12 -- metadata policy', () => {
      expect(() => validate({ schema: metadataPolicySchema, data: metadataPolicyFigure12 })).not.toThrow()
    })

    it('should validate figure 17 -- constraints', () => {
      expect(() => validate({ schema: constraintSchema, data: constraintsFigure17 })).not.toThrow()
    })

    it('should validate figure 18 -- entity configuration', () => {
      expect(() =>
        validate({
          schema: entityConfigurationClaimsSchema,
          data: entityConfigurationFigure18,
        })
      ).not.toThrow()
    })

    it('should validate figure 19 -- trust mark claims', () => {
      expect(() =>
        validate({
          schema: trustMarkClaimsSchema,
          data: trustMarkClaimsFigure19,
        })
      ).not.toThrow()
    })

    it('should validate figure 20 -- trust mark claims', () => {
      expect(() =>
        validate({
          schema: trustMarkClaimsSchema,
          data: trustMarkClaimsFigure20,
        })
      ).not.toThrow()
    })

    it('should validate figure 21 -- trust mark claims', () => {
      expect(() =>
        validate({
          schema: trustMarkClaimsSchema,
          data: trustMarkClaimsFigure21,
        })
      ).not.toThrow()
    })

    it('should validate figure 22 -- trust mark claims', () => {
      expect(() =>
        validate({
          schema: trustMarkClaimsSchema,
          data: trustMarkClaimsFigure22,
        })
      ).not.toThrow()
    })

    it('should validate figure 23 -- trust mark claims', () => {
      expect(() =>
        validate({
          schema: trustMarkClaimsSchema,
          data: trustMarkClaimsFigure23,
        })
      ).not.toThrow()
    })

    it('should validate figure 24 -- trust mark claims', () => {
      expect(() =>
        validate({
          schema: trustMarkClaimsSchema,
          data: trustMarkClaimsFigure24,
        })
      ).not.toThrow()
    })

    it('should validate figure 26 -- entity statement', () => {
      expect(() =>
        validate({
          schema: entityStatementClaimsSchema,
          data: entityStatementFigure26,
        })
      ).not.toThrow()
    })

    it('should validate figure 43 -- entity configuration', () => {
      expect(() =>
        validate({
          schema: entityConfigurationClaimsSchema,
          data: entityConfigurationFigure43,
        })
      ).not.toThrow()
    })

    it('should validate figure 50 -- entity configuration', () => {
      expect(() =>
        validate({
          schema: entityConfigurationClaimsSchema,
          data: entityConfigurationFigure50,
        })
      ).not.toThrow()
    })

    it('should validate figure 52 -- entity configuration', () => {
      expect(() =>
        validate({
          schema: entityConfigurationClaimsSchema,
          data: entityConfigurationFigure52,
        })
      ).not.toThrow()
    })

    it('should validate figure 54 -- entity statement', () => {
      expect(() =>
        validate({
          schema: entityStatementClaimsSchema,
          data: entityStatementFigure54,
        })
      ).not.toThrow()
    })

    it('should validate figure 56 -- entity configuration', () => {
      expect(() =>
        validate({
          schema: entityConfigurationClaimsSchema,
          data: entityConfigurationFigure56,
        })
      ).not.toThrow()
    })

    it('should validate figure 58 -- entity statement', () => {
      expect(() =>
        validate({
          schema: entityStatementClaimsSchema,
          data: entityStatementFigure58,
        })
      ).not.toThrow()
    })

    it('should validate figure 60 -- entity configutation', () => {
      expect(() =>
        validate({
          schema: entityConfigurationClaimsSchema,
          data: entityConfigurationFigure60,
        })
      ).not.toThrow()
    })

    it('should validate figure 62 -- entity statement', () => {
      expect(() =>
        validate({
          schema: entityStatementClaimsSchema,
          data: entityStatementFigure62,
        })
      ).not.toThrow()
    })

    it('should validate figure 63 -- metadata', () => {
      expect(() => validate({ schema: openIdProviderEntityMetadata.schema, data: metadataFigure63 })).not.toThrow()
    })

    it('should validate figure 69 -- entity configuration', () => {
      expect(() =>
        validate({
          schema: entityConfigurationClaimsSchema,
          data: entityConfigurationFigure69,
        })
      ).not.toThrow()
    })

    it('should validate figure 70 -- entity statement', () => {
      expect(() =>
        validate({
          schema: entityStatementClaimsSchema,
          data: entityStatementFigure70,
        })
      ).not.toThrow()
    })
  })
})
