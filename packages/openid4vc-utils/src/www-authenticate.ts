// A backslash escapes the character after it in a quoted string (RFC 9110 §5.6.4), not only a quote
const unquote = (value: string) => value.substring(1, value.length - 1).replace(/\\(.)/g, '$1')
// Fixup quoted strings and tokens with spaces around them
const sanitize = (value: string) => (value.charAt(0) === '"' ? unquote(value) : value.trim())

// lol dis
const body =
  // biome-ignore lint/suspicious/noControlCharactersInRegex: no explanation
  /((?:[a-zA-Z0-9._~+/-]+=*(?:\s+|$))|[^\u0000-\u001F\u007F()<>@,;:\\"/?={}[\]\u0020\u0009]+)(?:=([^\\"=\s,]+|"(?:[^"\\]|\\.)*"))?/g

export interface WwwAuthenticateHeaderChallenge {
  scheme: string

  /**
   * Record where the keys are the names, and the value can be 0 (null), 1 (string) or multiple (string[])
   * entries. Entries with an `undefined` value are omitted when encoding.
   */
  payload: Record<string, string | string[] | null | undefined>
}

const parsePayload = (scheme: string, string: string): WwwAuthenticateHeaderChallenge => {
  const payload: Record<string, string | string[] | null> = {}

  while (true) {
    const res = body.exec(string)
    if (!res) break

    const [, key, newValue] = res

    const payloadValue = payload[key]
    if (newValue) {
      const sanitizedValue = sanitize(newValue)
      payload[key] = payloadValue
        ? Array.isArray(payloadValue)
          ? [...payloadValue, sanitizedValue]
          : [payloadValue, sanitizedValue]
        : sanitizedValue
    } else if (!payloadValue) {
      payload[key] = null
    }
  }

  return { scheme, payload }
}

export function parseWwwAuthenticateHeader(str: string): WwwAuthenticateHeaderChallenge[] {
  const start = str.indexOf(' ')
  let scheme = str.substring(0, start)
  let value = str.substring(start)

  const challenges: WwwAuthenticateHeaderChallenge[] = []

  // Some well-known schemes to support-multi parsing
  const endsWithSchemeRegex = /, ?(Bearer|DPoP|Basic)$/
  const endsWithSchemeTest = endsWithSchemeRegex.exec(value)
  let endsWithScheme: string | undefined
  if (endsWithSchemeTest) {
    value = value.substring(0, value.length - endsWithSchemeTest[0].length)
    endsWithScheme = endsWithSchemeTest[1]
  }

  const additionalSchemesRegex = /(.*?)(, ?)(Bearer|DPoP|Basic)[, ]/
  let match = additionalSchemesRegex.exec(value)
  while (match) {
    challenges.push(parsePayload(scheme, match[1]))
    value = value.substring(match[0].length - 1)
    scheme = match[3]

    match = additionalSchemesRegex.exec(value)
  }
  challenges.push(parsePayload(scheme, value))
  if (endsWithScheme) {
    challenges.push({ scheme: endsWithScheme, payload: {} })
  }
  return challenges
}

/**
 * Replaces every run of characters outside visible ASCII and space with a single space.
 *
 * A value is often an error message, which can hold line breaks and input from whoever sent the
 * request. A CR or LF would end the header there, and `Headers.set` rejects it as well as any
 * character above U+00FF. RFC 6750 §3 limits `error_description` to a subset of the characters
 * that are kept in any case.
 */
const toHeaderText = (value: string) => value.replace(/[^\x20-\x7E]+/g, ' ')

/**
 * `error_description` is meant for a developer reading it, and is mostly filled from an error
 * message, so it is cut off rather than letting the message decide how large the header gets.
 */
const MAX_ERROR_DESCRIPTION_LENGTH = 500

/**
 * Encodes challenges as the value of a `WWW-Authenticate` header.
 *
 * The result is always a value a header can carry, whatever the challenges hold: every run of
 * characters outside visible ASCII and space is replaced with a single space, and an
 * `error_description` longer than 500 characters is cut off.
 */
export function encodeWwwAuthenticateHeader(challenges: WwwAuthenticateHeaderChallenge[]) {
  const entries: string[] = []

  for (const challenge of challenges) {
    // Encode each parameter according to RFC 7235
    const encodedParams = Object.entries(challenge.payload).flatMap(([key, value]) => {
      if (value === undefined) return []

      const name = toHeaderText(key)
      const encode = (s: string) => {
        let text = toHeaderText(s)
        if (key === 'error_description' && text.length > MAX_ERROR_DESCRIPTION_LENGTH) {
          text = `${text.slice(0, MAX_ERROR_DESCRIPTION_LENGTH - 3)}...`
        }

        // Escaped last, so that cutting off cannot split an escape
        return text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
      }

      if (Array.isArray(value)) {
        return value.map((v) => `${name}="${encode(v)}"`)
      }

      return value ? `${name}="${encode(value)}"` : name
    })

    const scheme = toHeaderText(challenge.scheme)
    entries.push(encodedParams.length === 0 ? scheme : `${scheme} ${encodedParams.join(', ')}`)
  }

  return entries.join(', ')
}
