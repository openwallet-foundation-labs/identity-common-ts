import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, expect } from 'vitest'

// Vitest isolates modules per test file, so every test file gets its own server
export const server = setupServer()

/**
 *
 * Intercepts global fetch for the tests of the calling file. Requests without a mocked response fail.
 *
 */
export const setupMockServer = () => {
  beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
  afterEach(() => server.resetHandlers())
  afterAll(() => server.close())
}

export type MockedResponse = {
  /**
   * Asserts that the mocked response was requested
   */
  done: () => void
}

/**
 *
 * Responds once to a GET request of the url. When `query` is given, only a request with these search parameters
 * matches.
 *
 */
export const mockGet = (
  url: string,
  {
    status = 200,
    body,
    contentType = 'application/entity-statement+jwt',
    query,
  }: { status?: number; body?: string; contentType?: string; query?: Record<string, string> } = {}
): MockedResponse => {
  let requested = false

  server.use(
    http.get(url, ({ request }) => {
      const { searchParams } = new URL(request.url)
      if (requested || (query && Object.entries(query).some(([key, value]) => searchParams.get(key) !== value))) {
        // Fall through to the next handler
        return
      }

      requested = true
      return new HttpResponse(body, { status, headers: body === undefined ? {} : { 'content-type': contentType } })
    })
  )

  return {
    done: () => expect(requested, `expected a GET request to '${url}'`).toBe(true),
  }
}
