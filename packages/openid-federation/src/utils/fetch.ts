import { isMediaType } from '@owf/identity-common'
import type { z } from 'zod'
import type { FetchCallback } from './types'
import { addSearchParams } from './url'
import { validate } from './validate'

// Resolved on every call, so a fetch that is set or replaced after this module is loaded is used
const defaultFetch: FetchCallback = (input, init) => globalThis.fetch(input, init)

type GetOptions = {
  url: string
  searchParams?: Record<string, string>
  requiredContentType?: string
  fetchCallback?: FetchCallback
}

/**
 *
 * Fetch the url and return the JSON response validated against the schema, or the text response without a schema
 *
 */
async function get<T extends z.ZodType>(options: GetOptions & { responseValidationSchema: T }): Promise<z.output<T>>
async function get(options: GetOptions & { responseValidationSchema?: undefined }): Promise<string>
async function get({
  url,
  searchParams,
  responseValidationSchema,
  requiredContentType,
  fetchCallback = defaultFetch,
}: GetOptions & { responseValidationSchema?: z.ZodType }): Promise<unknown> {
  // Fetch the url with the search params
  const urlSearchParams = new URLSearchParams(searchParams)
  const urlWithSearchParams = urlSearchParams.toString() ? addSearchParams(url, urlSearchParams) : url
  const response = await fetchCallback(urlWithSearchParams, {
    method: 'GET',
  })

  if (!response.ok) {
    throw new Error(`request to '${urlWithSearchParams}' failed with status ${response.status}`)
  }

  // validate the expected content-type, ignoring parameters such as `charset` and case (RFC 9110 8.3.1)
  if (requiredContentType && !isMediaType(response.headers.get('content-type'), requiredContentType)) {
    throw new Error(
      `received content-type '${response.headers.get(
        'content-type'
      )}' does not equal expected content-type '${requiredContentType}'`
    )
  }

  // If we pass in a validation schema, we expect JSON output
  if (responseValidationSchema) {
    const json = await response.json()
    return validate({
      data: json,
      schema: responseValidationSchema,
      errorMessage: 'invalid response from the GET call',
    })
  }

  // If no validation schema is passed in, we expect a string as response
  const text = await response.text()
  return text
}

/**
 *
 * @todo make get/post use the same method private internally as changes with apply to both
 *
 */
const post = async ({
  url,
  body,
  responseValidationSchema,
  fetchCallback = defaultFetch,
}: {
  url: string
  body?: Record<string, unknown>
  responseValidationSchema?: z.ZodType
  fetchCallback?: FetchCallback
}) => {
  const response = await fetchCallback(url, {
    method: 'POST',
    body: body ? JSON.stringify(body) : undefined,
    headers: { 'Content-Type': 'application/json' },
  })

  if (responseValidationSchema) {
    const json = await response.json()
    return validate({
      data: json,
      schema: responseValidationSchema,
      errorMessage: 'invalid response from a POST call',
    })
  }

  const text = await response.text()

  return text
}

export const fetcher = {
  get,
  post,
} as const
