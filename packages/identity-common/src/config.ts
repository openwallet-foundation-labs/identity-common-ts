export interface IdentityCommonConfig {
  /**
   * Whether to add the sensitive values of an error, such as an expected `state`, to its message.
   *
   * @default false
   */
  includeSensitiveErrorDetails: boolean
}

let IDENTITY_COMMON_CONFIG: IdentityCommonConfig = {
  includeSensitiveErrorDetails: false,
}

export function setIdentityCommonConfig(config: IdentityCommonConfig) {
  IDENTITY_COMMON_CONFIG = config
}

export function getIdentityCommonConfig(): IdentityCommonConfig {
  return IDENTITY_COMMON_CONFIG
}
