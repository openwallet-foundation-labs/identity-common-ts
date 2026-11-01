import { LoTEException } from './lote-exception'
import { TrustedEntitySchema, TrustedEntityServiceSchema } from './schemas'
import type {
  JWKPublicKey,
  PostalAddress,
  ServiceHistoryInstance,
  ServiceInformation,
  TrustedEntity,
  TrustedEntityInformation,
  TrustedEntityService,
} from './types'

/**
 * Builder for creating TrustedEntity objects with a fluent API
 */
export class TrustedEntityBuilder {
  private info: Partial<TrustedEntityInformation> = {}
  private services: TrustedEntityService[] = []

  /**
   * Set the entity name
   */
  name(value: string, lang = 'en'): this {
    this.info.TEName = this.info.TEName ?? []
    this.info.TEName.push({ lang, value })
    return this
  }

  /**
   * Set the trade name
   */
  tradeName(value: string, lang = 'en'): this {
    this.info.TETradeName = this.info.TETradeName ?? []
    this.info.TETradeName.push({ lang, value })
    return this
  }

  /**
   * Set the postal address
   */
  postalAddress(address: Omit<PostalAddress, 'lang'>, lang = 'en'): this {
    this.info.TEAddress = this.info.TEAddress ?? {
      TEPostalAddress: [],
      TEElectronicAddress: [],
    }
    this.info.TEAddress.TEPostalAddress.push({ ...address, lang })
    return this
  }

  /**
   * Add an electronic address (email)
   */
  email(email: string, lang = 'en'): this {
    this.info.TEAddress = this.info.TEAddress ?? {
      TEPostalAddress: [],
      TEElectronicAddress: [],
    }
    this.info.TEAddress.TEElectronicAddress.push({
      lang,
      uriValue: email.startsWith('mailto:') ? email : `mailto:${email}`,
    })
    return this
  }

  /**
   * Add an information URI
   */
  infoUri(uri: string, lang = 'en'): this {
    this.info.TEInformationURI = this.info.TEInformationURI ?? []
    this.info.TEInformationURI.push({ lang, uriValue: uri })
    return this
  }

  /**
   * Add a website URL as an electronic address
   */
  website(url: string, lang = 'en'): this {
    this.info.TEAddress = this.info.TEAddress ?? {
      TEPostalAddress: [],
      TEElectronicAddress: [],
    }
    this.info.TEAddress.TEElectronicAddress.push({
      lang,
      uriValue: url.startsWith('http') ? url : `https://${url}`,
    })
    return this
  }

  /**
   * Add custom extensions
   */
  addExtension(extension: unknown): this {
    this.info.TEInformationExtensions = this.info.TEInformationExtensions ?? []
    this.info.TEInformationExtensions.push(extension)
    return this
  }

  /**
   * Add a service to the entity
   */
  addService(service: TrustedEntityService): this {
    this.services.push(service)
    return this
  }

  /**
   * Build the TrustedEntity object
   */
  build(): TrustedEntity {
    const result = TrustedEntitySchema.safeParse({
      TrustedEntityInformation: this.info,
      TrustedEntityServices: this.services,
    })

    if (!result.success) {
      const messages = result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n')
      throw new LoTEException(`Invalid TrustedEntity:\n${messages}`)
    }

    return result.data
  }
}

/**
 * Builder for creating TrustedEntityService objects
 */
export class ServiceBuilder {
  private info: Partial<ServiceInformation> = {}
  private history: ServiceHistoryInstance[] = []

  /**
   * Set the service name
   */
  name(value: string, lang = 'en'): this {
    this.info.ServiceName = this.info.ServiceName ?? []
    this.info.ServiceName.push({ lang, value })
    return this
  }

  /**
   * Set the service type identifier
   */
  type(typeUri: string): this {
    this.info.ServiceTypeIdentifier = typeUri
    return this
  }

  /**
   * Set the service status
   */
  status(statusUri: string, startingTime?: Date): this {
    this.info.ServiceStatus = statusUri
    this.info.StatusStartingTime = startingTime?.toISOString() ?? new Date().toISOString()
    return this
  }

  /**
   * Add an X.509 certificate to the digital identity
   */
  addCertificate(certBase64: string): this {
    this.info.ServiceDigitalIdentity = this.info.ServiceDigitalIdentity ?? {}
    this.info.ServiceDigitalIdentity.X509Certificates = this.info.ServiceDigitalIdentity.X509Certificates ?? []
    this.info.ServiceDigitalIdentity.X509Certificates.push({
      encoding: 'urn:ietf:params:tls-cert-type:x509',
      specRef: 'RFC5280',
      val: certBase64,
    })
    return this
  }

  /**
   * Add an X.509 subject name (DN format) to the digital identity
   */
  addX509SubjectName(subjectName: string): this {
    this.info.ServiceDigitalIdentity = this.info.ServiceDigitalIdentity ?? {}
    this.info.ServiceDigitalIdentity.X509SubjectNames = this.info.ServiceDigitalIdentity.X509SubjectNames ?? []
    this.info.ServiceDigitalIdentity.X509SubjectNames.push(subjectName)
    return this
  }

  /**
   * Add an X.509 Subject Key Identifier (base64-encoded) to the digital identity
   */
  addX509SKI(ski: string): this {
    this.info.ServiceDigitalIdentity = this.info.ServiceDigitalIdentity ?? {}
    this.info.ServiceDigitalIdentity.X509SKIs = this.info.ServiceDigitalIdentity.X509SKIs ?? []
    this.info.ServiceDigitalIdentity.X509SKIs.push(ski)
    return this
  }

  /**
   * Add another identifier to the digital identity
   */
  addOtherId(id: string): this {
    this.info.ServiceDigitalIdentity = this.info.ServiceDigitalIdentity ?? {}
    this.info.ServiceDigitalIdentity.OtherIds = this.info.ServiceDigitalIdentity.OtherIds ?? []
    this.info.ServiceDigitalIdentity.OtherIds.push(id)
    return this
  }

  /**
   * Add a public key (JWK) to the digital identity
   */
  addPublicKey(jwk: JWKPublicKey): this {
    this.info.ServiceDigitalIdentity = this.info.ServiceDigitalIdentity ?? {}
    this.info.ServiceDigitalIdentity.PublicKeyValues = this.info.ServiceDigitalIdentity.PublicKeyValues ?? []
    this.info.ServiceDigitalIdentity.PublicKeyValues.push(jwk)
    return this
  }

  /**
   * Add a service endpoint (service supply point): `addEndpoint(uri)` for a bare
   * `{ uriValue }`, as the EC PID and wallet lists use, or `addEndpoint(type, uri)`.
   */
  addEndpoint(uri: string): this
  addEndpoint(type: string | undefined, uri: string): this
  addEndpoint(...args: [string] | [string | undefined, string]): this {
    // On the number of arguments, so a JavaScript call addEndpoint(type, undefined) keeps its type
    const [type, uriValue] = args.length === 1 ? [undefined, args[0]] : args
    this.info.ServiceSupplyPoints = this.info.ServiceSupplyPoints ?? []
    this.info.ServiceSupplyPoints.push(type === undefined ? { uriValue } : { ServiceType: type, uriValue })
    return this
  }

  /**
   * Add a service definition URI
   */
  addDefinitionUri(uri: string, lang = 'en'): this {
    this.info.ServiceDefinitionURI = this.info.ServiceDefinitionURI ?? []
    this.info.ServiceDefinitionURI.push({ lang, uriValue: uri })
    return this
  }

  /**
   * Add custom service information extensions
   */
  addExtension(extension: unknown): this {
    this.info.ServiceInformationExtensions = this.info.ServiceInformationExtensions ?? []
    this.info.ServiceInformationExtensions.push(extension)
    return this
  }

  /**
   * Add a historical service instance
   */
  addHistoryEntry(historyInstance: ServiceHistoryInstance): this {
    this.history.push(historyInstance)
    return this
  }

  /**
   * Build the TrustedEntityService object
   */
  build(): TrustedEntityService {
    const data: Record<string, unknown> = {
      ServiceInformation: this.info,
    }

    if (this.history.length > 0) {
      data.ServiceHistory = this.history
    }

    const result = TrustedEntityServiceSchema.safeParse(data)

    if (!result.success) {
      const messages = result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n')
      throw new LoTEException(`Invalid TrustedEntityService:\n${messages}`)
    }

    return result.data
  }
}

/**
 * Create a new TrustedEntityBuilder
 */
export function trustedEntity(): TrustedEntityBuilder {
  return new TrustedEntityBuilder()
}

/**
 * Create a new ServiceBuilder
 */
export function service(): ServiceBuilder {
  return new ServiceBuilder()
}
