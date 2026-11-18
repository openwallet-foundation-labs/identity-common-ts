import type { TypeMetadataFormat } from './sd-jwt-vc-type-metadata-format'

export type VctFetcher = (uri: string, integrity?: string) => Promise<TypeMetadataFormat | undefined>
