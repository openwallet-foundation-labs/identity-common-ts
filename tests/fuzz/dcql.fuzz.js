import { DcqlQuery } from 'dcql'

export function fuzz(data) {
  try {
    const input = JSON.parse(data.toString('utf-8'))
    DcqlQuery.parse(input)
  } catch (_error) {
    // JSON parse or validation errors on malformed query inputs are expected
  }
}
