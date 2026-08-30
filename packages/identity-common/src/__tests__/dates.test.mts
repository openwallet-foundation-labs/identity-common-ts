import { describe, expect, it } from 'vitest'
import { dateToSeconds, nowInSeconds, secondsToDate } from '../../src'

describe('dates', () => {
  it('should round-trip a whole-second date', () => {
    const date = new Date('2026-03-01T12:00:00.000Z')
    expect(secondsToDate(dateToSeconds(date))).toEqual(date)
  })

  it('should truncate sub-second precision rather than round it', () => {
    expect(dateToSeconds(new Date('2026-03-01T12:00:00.999Z'))).toBe(
      dateToSeconds(new Date('2026-03-01T12:00:00.000Z'))
    )
  })

  it('should convert seconds to a date', () => {
    expect(secondsToDate(1_700_000_000).toISOString()).toBe('2023-11-14T22:13:20.000Z')
  })

  it('should return the current time in seconds', () => {
    const before = Math.floor(Date.now() / 1000)
    const now = nowInSeconds()
    expect(now).toBeGreaterThanOrEqual(before)
    expect(now).toBeLessThanOrEqual(Math.floor(Date.now() / 1000))
  })
})
