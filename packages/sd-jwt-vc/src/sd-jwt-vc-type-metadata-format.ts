import { z } from 'zod'

export const zBackgroundImage = z.looseObject({
  /** REQUIRED. A URI pointing to the background image. */
  uri: z.string(),
  /** OPTIONAL. An "integrity metadata" string as described in Section 7. */
  'uri#integrity': z.string().optional(),
})
export type BackgroundImage = z.infer<typeof zBackgroundImage>

/**
 * Logo metadata used in rendering a credential.
 */
export const zLogo = z.looseObject({
  /** REQUIRED. A URI pointing to the logo image. */
  uri: z.string(),
  /** OPTIONAL. An "integrity metadata" string as described in Section 7. */
  'uri#integrity': z.string().optional(),
  /** OPTIONAL. A string containing alternative text for the logo image. */
  alt_text: z.string().optional(),
})

export type Logo = z.infer<typeof zLogo>

/**
 * The simple rendering method is intended for applications that do not support SVG.
 */
export const zSimpleRendering = z.looseObject({
  /** OPTIONAL. Logo metadata to display for the credential. */
  logo: zLogo.optional(),
  /** OPTIONAL. RGB color value for the credential background (e.g., "#FFFFFF"). */
  background_color: z.string().optional(),
  /** OPTIONAL. RGB color value for the credential text (e.g., "#000000"). */
  text_color: z.string().optional(),
  /** OPTIONAL. An object containing information about the background image to be displayed for the type. */
  background_image: zBackgroundImage.optional(),
})

export type SimpleRendering = z.infer<typeof zSimpleRendering>

/** Enum of valid values for rendering orientation. */
export const zOrientation = z.enum(['portrait', 'landscape'])

/** Enum of valid values for rendering color schemes. */
export const zColorScheme = z.enum(['light', 'dark'])

/** Enum of valid values for rendering contrast. */
export const zContrast = z.enum(['normal', 'high'])

/**
 * Properties that describe the display preferences for an SVG template rendering.
 */
export const zSvgTemplateProperties = z.looseObject({
  /** OPTIONAL. Orientation optimized for the template. */
  orientation: zOrientation.optional(),
  /** OPTIONAL. Color scheme optimized for the template. */
  color_scheme: zColorScheme.optional(),
  /** OPTIONAL. Contrast level optimized for the template. */
  contrast: zContrast.optional(),
})

export type SvgTemplateProperties = z.infer<typeof zSvgTemplateProperties>

/**
 * SVG rendering metadata containing URI and optional integrity and properties.
 */
export const zSvgTemplateRendering = z.looseObject({
  /** REQUIRED. A URI pointing to the SVG template. */
  uri: z.string(),
  /** OPTIONAL. An "integrity metadata" string as described in Section 7. */
  'uri#integrity': z.string().optional(),
  /** REQUIRED if more than one SVG template is present. */
  properties: zSvgTemplateProperties.optional(),
})

export type SvgTemplateRendering = z.infer<typeof zSvgTemplateRendering>

/**
 * Rendering metadata, either simple or SVG-based, for a credential.
 */
export const zRendering = z
  .looseObject({
    /** OPTIONAL. Simple rendering metadata. */
    simple: zSimpleRendering.optional(),
    /** OPTIONAL. Array of SVG template rendering objects. */
    svg_templates: z.array(zSvgTemplateRendering).optional(),
    /**
     * OPTIONAL. Array of SVG template rendering objects.
     * @deprecated use `svg_templates` (plural) instead.
     */
    svg_template: z.array(zSvgTemplateRendering).optional(),
  })
  .transform(({ svg_template, svg_templates = svg_template, ...rest }) => ({
    ...rest,
    ...(svg_templates && { svg_templates }),
  }))

export type Rendering = z.infer<typeof zRendering>

/**
 * Display metadata associated with a credential type.
 */
export const zDisplay = z
  .looseObject({
    /**
     * Language tag according to RFC 5646 (e.g., "en", "de").
     * @deprecated - use `locale` instead
     */
    lang: z.string().optional(),

    /**
     * REQUIRED (preferred). Language tag according to RFC 5646.
     * Alias for `lang` - either `lang` or `locale` must be provided.
     */
    locale: z.string().optional(),

    /** REQUIRED. Human-readable name for the credential type. */
    name: z.string(),
    /** OPTIONAL. Description of the credential type for end users. */
    description: z.string().optional(),
    /** OPTIONAL. Rendering information (simple or SVG) for the credential. */
    rendering: zRendering.optional(),
  })
  .transform(({ lang, locale, ...rest }) => ({
    ...rest,
    locale: locale ?? lang,
  }))
  .refine(({ locale }) => locale !== undefined, {
    message: 'Either locale (preferred) or lang (spec name, deprecated) MUST be defined on claim display entry.',
  })

export type Display = z.infer<typeof zDisplay>

/**
 * Claim path within the credential's JSON structure.
 * Example: ["address", "street_address"]
 */
export const zClaimPath = z.array(z.string().nullable())

export type ClaimPath = z.infer<typeof zClaimPath>

/**
 * Display metadata for a specific claim.
 */
export const zClaimDisplay = z
  .looseObject({
    /**
     * Language tag according to RFC 5646.
     * @deprecated - use `locale` instead
     */
    lang: z.string().optional(),

    /**
     * REQUIRED (preferred). Language tag according to RFC 5646.
     * Alias for `lang` - either `lang` or `locale` must be provided.
     */
    locale: z.string().optional(),

    /** REQUIRED. Human-readable label for the claim. */
    label: z.string().optional(),

    /**
     * Human-readable label for the claim.
     * @deprecated - use `label` instead
     */
    name: z.string().optional(),

    /** OPTIONAL. Description of the claim for end users. */
    description: z.string().optional(),
  })
  .transform(({ lang, name, label, locale, ...rest }) => ({
    ...rest,
    locale: locale ?? lang,
    label: label ?? name,
  }))
  .refine(({ locale }) => locale !== undefined, {
    message: 'Either locale (preferred) or lang (deprecated) MUST be defined on claim display entry.',
  })
  .refine(({ label }) => label !== undefined, {
    message: 'Either label (preferred) or name (deprecated) MUST be defined on claim display entry.',
  })

export type ClaimDisplay = z.infer<typeof zClaimDisplay>

/**
 * Indicates whether a claim is selectively disclosable.
 */
export const zClaimSelectiveDisclosure = z.enum(['always', 'allowed', 'never'])

export type ClaimSelectiveDisclosure = z.infer<typeof zClaimSelectiveDisclosure>

/**
 * Metadata for individual claims in the credential type.
 */
export const zClaim = z.looseObject({
  /**
   * REQUIRED. Array of one or more paths to the claim in the credential subject.
   * Each path is an array of strings (or null for array elements).
   */
  path: zClaimPath,
  /** OPTIONAL. Display metadata in multiple languages. */
  display: z.array(zClaimDisplay).optional(),
  /** OPTIONAL. Controls whether the claim must, may, or must not be selectively disclosed. */
  sd: zClaimSelectiveDisclosure.optional(),
  /**
   * OPTIONAL. A boolean indicating whether the claim must be present in the Unsecured Payload
   * of the SD-JWT VC. Default is false if not specified.
   */
  mandatory: z.boolean().optional(),
  /**
   * OPTIONAL. Unique string identifier for referencing the claim in an SVG template.
   * Must consist of alphanumeric characters or underscores and must not start with a digit.
   */
  svg_id: z.string().optional(),
})

export type Claim = z.infer<typeof zClaim>

/**
 * Type metadata for a specific Verifiable Credential (VC) type.
 * Reference: https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-13.html#name-type-metadata-format
 */
export const zTypeMetadataFormat = z.looseObject({
  /** REQUIRED. A URI uniquely identifying the credential type. */
  vct: z.string(),
  /** OPTIONAL. Human-readable name for developers. */
  name: z.string().optional(),
  /** OPTIONAL. Human-readable description for developers. */
  description: z.string().optional(),
  /** OPTIONAL. URI of another type that this one extends. */
  extends: z.string().optional(),
  /** OPTIONAL. Integrity metadata for the 'extends' field. */
  'extends#integrity': z.string().optional(),
  /** OPTIONAL. Array of localized display metadata for the type. */
  display: z.array(zDisplay).optional(),
  /** OPTIONAL. Array of claim metadata. */
  claims: z.array(zClaim).optional(),
})

/**
 * The resolved type metadata. If you just want to use the type metadata, you should use `typeMetadata`.
 * In case additional processing is needed (e.g. for extensions in type metadata), you can use the `typeMetadataChain`
 */
export type ResolvedTypeMetadata = {
  /**
   * The merged type metadata based on the resolved `vct` document and all `extends` values.
   */
  mergedTypeMetadata: TypeMetadataFormat

  /**
   * The original type metadata documents, ordered from the extending type to the last extended type.
   */
  typeMetadataChain: [TypeMetadataFormat, ...TypeMetadataFormat[]]

  /**
   * The vct values present in the type metadata chain. This can be used for matching against e.g.
   * DCQL queries which can query an underlying type.
   */
  vctValues: [string, ...string[]]
}

export type TypeMetadataFormat = z.infer<typeof zTypeMetadataFormat>
