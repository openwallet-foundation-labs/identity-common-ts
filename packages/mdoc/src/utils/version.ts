import type { VerificationCallback } from '../mdoc/check-callback'

/**
 * ISO/IEC 18013-5 8.1: a version is `major.minor`, and an unknown minor version of a known major
 * version must not cause an error. Every structure this library supports has major version 1.
 */
export const supportedVersionRegex = /^1\.\d+$/

export const isSupportedVersion = (version: string) => supportedVersionRegex.test(version)

/**
 * Report through `onCheck` whether the version of a structure has a major version this library
 * supports.
 */
export const verifyVersion = (
  options: { structure: string; version: string | undefined },
  onCheck: VerificationCallback
) => {
  const { structure, version } = options

  onCheck({
    status: version !== undefined && isSupportedVersion(version) ? 'PASSED' : 'FAILED',
    category: 'DOCUMENT_FORMAT',
    check: `${structure} must have a supported version`,
    reason:
      version !== undefined && isSupportedVersion(version)
        ? undefined
        : `${structure} has version '${version}', but only major version 1 is supported`,
  })
}
