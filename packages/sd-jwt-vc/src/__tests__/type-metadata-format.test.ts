import { describe, expect, test } from 'vitest'
import { RenderingSchema, type TypeMetadataFormat } from '../sd-jwt-vc-type-metadata-format'

const svgTemplate = { uri: 'https://example.com/template.svg' }

describe('RenderingSchema', () => {
  test('keeps svg_templates', () => {
    expect(RenderingSchema.parse({ svg_templates: [svgTemplate] })).toStrictEqual({ svg_templates: [svgTemplate] })
  })

  test('maps the deprecated svg_template to svg_templates', () => {
    expect(RenderingSchema.parse({ svg_template: [svgTemplate] })).toStrictEqual({ svg_templates: [svgTemplate] })
  })

  test('does not add svg_templates when not present', () => {
    expect(RenderingSchema.parse({ simple: { background_color: '#ffffff' } })).toStrictEqual({
      simple: { background_color: '#ffffff' },
    })
  })

  test('svg_templates is optional in the type', () => {
    const typeMetadata: TypeMetadataFormat = {
      vct: 'https://example.com/vct',
      display: [{ locale: 'en', name: 'Example', rendering: { simple: { background_color: '#ffffff' } } }],
    }

    expect(typeMetadata.display?.[0].rendering?.svg_templates).toBeUndefined()
  })
})
