export function addSecondsToDate(date: Date, seconds: number) {
  return new Date(date.getTime() + seconds * 1000)
}
