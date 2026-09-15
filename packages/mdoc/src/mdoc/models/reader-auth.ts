import { Sign1, type Sign1DecodedStructure, type Sign1EncodedStructure, type Sign1Options } from '@owf/cose'
import type { MdocContext } from '../../context'
import { defaultVerificationCallback, onCategoryCheck, type VerificationCallback } from '../check-callback'
import { ReaderAuthentication, type ReaderAuthenticationOptions } from './reader-authentication'

export type ReaderAuthEncodedStructure = Sign1EncodedStructure
export type ReaderAuthDecodedStructure = Sign1DecodedStructure
export type ReaderAuthOptions = Sign1Options

export class ReaderAuth extends Sign1 {
  public async verify(
    options: {
      readerAuthentication: ReaderAuthentication | ReaderAuthenticationOptions
      verificationCallback?: VerificationCallback
      /**
       * Trust anchors for the reader's certificate chain (e.g. CAs listed in a
       * RICAL). The chain in this Sign1's x5chain header is validated against
       * these anchors per RFC 5280. Without trust anchors the chain check FAILS,
       * unless `disableCertificateChainValidation` is set.
       */
      trustedCertificates?: Array<Uint8Array>
      /**
       * Only verify the detached signature, without establishing trust in the
       * reader's certificate chain. The reader is then not authenticated.
       */
      disableCertificateChainValidation?: boolean
      now?: Date
    },
    ctx: Pick<MdocContext, 'cose' | 'x509'>
  ) {
    const readerAuthentication =
      options.readerAuthentication instanceof ReaderAuthentication
        ? options.readerAuthentication
        : new ReaderAuthentication(options.readerAuthentication)

    const verificationCallback = options.verificationCallback ?? defaultVerificationCallback

    const onCheck = onCategoryCheck(verificationCallback, 'READER_AUTH')

    let isValid: boolean
    let reason: string | undefined
    try {
      // `certificate` throws when the reader auth has no x5chain, which is required (18013-5 9.1.4).
      isValid = await this.verifySignature(
        {
          key: await ctx.x509.getPublicKey({ certificate: this.certificate, algorithm: this.algorithm }),
          detachedPayload: readerAuthentication.encode({ asDataItem: true }),
        },
        { verify: ctx.cose.sign1.verify }
      )
      reason = isValid ? undefined : 'Signature is invalid on the reader auth'
    } catch (error) {
      isValid = false
      reason = `Unable to verify the reader auth signature: ${error instanceof Error ? error.message : 'Unknown error'}`
    }

    onCheck({
      status: isValid ? 'PASSED' : 'FAILED',
      check: 'Reader auth signature must be valid',
      reason,
    })

    if (!options.disableCertificateChainValidation) {
      try {
        if (!options.trustedCertificates || options.trustedCertificates.length === 0) {
          throw new Error('No trusted reader certificates provided.')
        }

        await ctx.x509.verifyCertificateChain({
          trustedCertificates: options.trustedCertificates,
          x5chain: this.certificateChain,
          now: options.now ?? new Date(),
        })

        onCheck({
          status: 'PASSED',
          check: 'Reader certificate chain must be trusted',
        })
      } catch (err) {
        onCheck({
          status: 'FAILED',
          check: 'Reader certificate chain must be trusted',
          reason: err instanceof Error ? err.message : 'Unknown error',
        })
      }
    }
  }

  public static create(options: ReaderAuthOptions) {
    // biome-ignore lint/complexity/noThisInStatic: `super.create` keeps `this` bound to the subclass
    return super.create(options) as ReaderAuth
  }
}
