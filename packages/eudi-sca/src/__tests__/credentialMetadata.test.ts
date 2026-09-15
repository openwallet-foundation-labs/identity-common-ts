import { HttpResponse, http } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, beforeAll, expect, suite, test } from 'vitest'
import { ZodError } from 'zod'
import { fetchCredentialMetadata, parseCredentialMetadata } from '../credentialMetadata'

export const credential_metadata = {
  transaction_data_types: {
    'urn:eudi:sca:com.example.pay:transaction:2': {
      claims: [
        {
          path: ['transaction_id'],
          mandatory: true,
        },
        {
          path: ['amount'],
          mandatory: true,
          value_type: 'iso_currency_amount',
          display: [
            { locale: 'en', name: 'amount' },
            { locale: 'de', name: 'betrag' },
          ],
        },
        {
          path: ['amount_estimated'],
          value_type: 'label_only',
          display: [
            { locale: 'en', name: 'amount is estimated' },
            { locale: 'de', name: 'betrag ist geschätzt' },
          ],
        },
        {
          path: ['amount_earmarked'],
          value_type: 'label_only',
          display: [
            { locale: 'en', name: 'amount earmarked immediately' },
            { locale: 'de', name: 'betrag sofort reserviert' },
          ],
        },
        {
          path: ['payee', 'name'],
          mandatory: true,
          display: [
            { locale: 'en', name: 'payee' },
            { locale: 'de', name: 'empfänger' },
          ],
        },
        {
          path: ['payee', 'id'],
          mandatory: true,
        },
        {
          path: ['payee', 'logo'],
          value_type: 'image',
          display: [
            { locale: 'en', name: 'payee logo' },
            { locale: 'de', name: 'empfänger-logo' },
          ],
        },
        {
          path: ['payee', 'logo#integrity'],
        },
        {
          path: ['payee', 'website'],
          value_type: 'url',
          display: [
            { locale: 'en', name: 'website' },
            { locale: 'de', name: 'webseite' },
          ],
        },
        {
          path: ['remittance_info'],
          display: [
            { locale: 'en', name: 'reference' },
            { locale: 'de', name: 'verwendungszweck' },
          ],
        },
        {
          path: ['execution_date'],
          value_type: 'iso_date',
          display: [
            { locale: 'en', name: 'execution date' },
            { locale: 'de', name: 'ausführungsdatum' },
          ],
        },
        {
          path: ['date_time'],
          value_type: 'iso_date_time',
          display: [
            { locale: 'en', name: 'initiated' },
            { locale: 'de', name: 'eingeleitet' },
          ],
        },
      ],
      ui_labels: {
        affirmative_action_label: [
          { locale: 'en', value: 'Confirm Payment' },
          { locale: 'de', value: 'Zahlung bestätigen' },
        ],
        denial_action_label: [
          { locale: 'en', value: 'Cancel' },
          { locale: 'de', value: 'Abbrechen' },
        ],
        transaction_title: [
          { locale: 'en', value: 'Payment Confirmation' },
          { locale: 'de', value: 'Zahlungsbestätigung' },
        ],
        security_hint: [
          { locale: 'en', value: 'Verify that the payee name matches the intended recipient' },
          { locale: 'de', value: 'Prüfen Sie, ob der Empfängername mit dem beabsichtigten Empfänger übereinstimmt' },
        ],
      },
    },
  },
}

suite('parse credential metadata', () => {
  test('parse valid credential metadata', () => {
    const credentialMetadata = parseCredentialMetadata(credential_metadata)
    expect(credentialMetadata).toMatchObject(credential_metadata)
  })

  test('parse invalid credential metadata with incorrect key', () => {
    expect(() =>
      parseCredentialMetadata({
        transaction_data_types: {
          'invalid:urn:key': credential_metadata.transaction_data_types['urn:eudi:sca:com.example.pay:transaction:2'],
        },
      })
    ).toThrow(ZodError)
  })

  test('parse invalid credential metadata with incorrect value_type', () => {
    const invalidCm = structuredClone(credential_metadata)
    invalidCm.transaction_data_types['urn:eudi:sca:com.example.pay:transaction:2'].claims[0].value_type = 'invalid'
    expect(() => parseCredentialMetadata(invalidCm)).toThrow(ZodError)
  })
})

const credentialMetadataJwt =
  'eyJhbGciOiJFUzI1NiIsInR5cCI6ImNyZWRlbnRpYWwtbWV0YWRhdGErand0IiwieDVjIjpbIi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLVxuTUlJQ0VEQ0NBYldnQXdJQkFnSVFISXBlMzNETUVQak9uYitOdmRPeGl6QUtCZ2dxaGtqT1BRUURBakFkTVE0d1xuREFZRFZRUURFd1ZCYm1sdGJ6RUxNQWtHQTFVRUJoTUNUa3d3SGhjTk1qWXdNekU1TVRReU9UQXpXaGNOTWpjd1xuTkRBNE1UUXlPVEF6V2pBaE1SSXdFQVlEVlFRREV3bGpjbVZrYnlCa1kzTXhDekFKQmdOVkJBWVRBazVNTUZrd1xuRXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVscEdmcXJhSzViWGlpc0JraWZjSTY3U3ZCSWprSk9qMFxuOG4xcmRSdzZud0dVd3R5bDNIMXM1UDM4STFBZ3B5QVlLVVUwdjlpbmRLaWZZcDRpZWNPeExhT0IwakNCenpBZFxuQmdOVkhRNEVGZ1FVd0ZCa2NqOHQrajBhQ2pyR24zYUtUUkhKdmRNd0RnWURWUjBQQVFIL0JBUURBZ2VBTUJVR1xuQTFVZEpRRUIvd1FMTUFrR0J5aUJqRjBGQVFJd0h3WURWUjBqQkJnd0ZvQVVnNlV3UDZCRFpqZTlUdlRuYll5elxucjZCWldvUXdOZ1lEVlIwU0JDOHdMWVlyYUhSMGNITTZMeTgyT0RBd0xURTNPQzB5TWpVdE1UTTBMVEl4TlM1dVxuWjNKdmF5MW1jbVZsTG1Gd2NEQXVCZ05WSFJFRUp6QWxnaU0yT0RBd0xURTNPQzB5TWpVdE1UTTBMVEl4TlM1dVxuWjNKdmF5MW1jbVZsTG1Gd2NEQUtCZ2dxaGtqT1BRUURBZ05KQURCR0FpRUFxVzlJcUZTUEZBZ3hJbDdvWFZ2d1xuVHd0TDRaZjJKYUs0aWVnWkhqcDgzL01DSVFDWG04aUd3R2ZucDJuMG5nNWtVRWRXVU02SlZ4YWJoSlZESU4rZFxuSmhEV25BPT1cbi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0iXX0.eyJmb3JtYXQiOiJkYytzZC1qd3QiLCJjcmVkZW50aWFsX21ldGFkYXRhX3VyaSI6Imh0dHBzOi8vNjgwMC0xNzgtMjI1LTEzNC0yMTUubmdyb2stZnJlZS5hcHAvcGF5bWVudHMtY3JlZGVudGlhbC1tZXRhZGF0YSIsImNyZWRlbnRpYWxfbWV0YWRhdGEiOnsiY3JlZGVudGlhbF9pc3N1ZXIiOiJodHRwczovLzY4MDAtMTc4LTIyNS0xMzQtMjE1Lm5ncm9rLWZyZWUuYXBwL29pZDR2Y2kvN2NjMDI4YTMtOGNlMi00MzJhLWJmMTktNTYyMTA2ODU4NmRmIiwiY3JlZGVudGlhbF9lbmRwb2ludCI6Imh0dHBzOi8vNjgwMC0xNzgtMjI1LTEzNC0yMTUubmdyb2stZnJlZS5hcHAvb2lkNHZjaS83Y2MwMjhhMy04Y2UyLTQzMmEtYmYxOS01NjIxMDY4NTg2ZGYvY3JlZGVudGlhbCIsImRlZmVycmVkX2NyZWRlbnRpYWxfZW5kcG9pbnQiOiJodHRwczovLzY4MDAtMTc4LTIyNS0xMzQtMjE1Lm5ncm9rLWZyZWUuYXBwL29pZDR2Y2kvN2NjMDI4YTMtOGNlMi00MzJhLWJmMTktNTYyMTA2ODU4NmRmL2RlZmVycmVkLWNyZWRlbnRpYWwiLCJjcmVkZW50aWFsX2NvbmZpZ3VyYXRpb25zX3N1cHBvcnRlZCI6eyJ3ZXJvLWNhcmQtc2Qtand0Ijp7ImZvcm1hdCI6ImRjK3NkLWp3dCIsInZjdCI6ImV1LmV1cm9wYS53ZXJvLmNhcmQiLCJzY29wZSI6Indlcm8tY2FyZC1zZC1qd3QiLCJjcnlwdG9ncmFwaGljX2JpbmRpbmdfbWV0aG9kc19zdXBwb3J0ZWQiOlsiandrIl0sImNyZWRlbnRpYWxfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJFZERTQSIsIkVTMjU2Il0sInByb29mX3R5cGVzX3N1cHBvcnRlZCI6eyJqd3QiOnsicHJvb2Zfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJFUzI1NiIsIkVkRFNBIl19fSwiZGlzcGxheSI6W3sibG9jYWxlIjoiZW4iLCJuYW1lIjoiV2VybyBCYW5rIEFjY291bnQiLCJ0ZXh0X2NvbG9yIjoiIzFEMUMxQyIsImJhY2tncm91bmRfY29sb3IiOiIjZmZmNDhkIiwiYmFja2dyb3VuZF9pbWFnZSI6eyJ1cmkiOiJodHRwczovLzY4MDAtMTc4LTIyNS0xMzQtMjE1Lm5ncm9rLWZyZWUuYXBwL2Fzc2V0cy9jcmVkZW50aWFscy93ZXJvX2JhY2tncm91bmQuanBlZyIsInVybCI6Imh0dHBzOi8vNjgwMC0xNzgtMjI1LTEzNC0yMTUubmdyb2stZnJlZS5hcHAvYXNzZXRzL2NyZWRlbnRpYWxzL3dlcm9fYmFja2dyb3VuZC5qcGVnIn19XSwiY3JlZGVudGlhbF9tZXRhZGF0YSI6eyJkaXNwbGF5IjpbeyJsb2NhbGUiOiJlbiIsIm5hbWUiOiJXZXJvIEJhbmsgQWNjb3VudCIsInRleHRfY29sb3IiOiIjMUQxQzFDIiwiYmFja2dyb3VuZF9jb2xvciI6IiNmZmY0OGQiLCJiYWNrZ3JvdW5kX2ltYWdlIjp7InVyaSI6Imh0dHBzOi8vNjgwMC0xNzgtMjI1LTEzNC0yMTUubmdyb2stZnJlZS5hcHAvYXNzZXRzL2NyZWRlbnRpYWxzL3dlcm9fYmFja2dyb3VuZC5qcGVnIiwidXJsIjoiaHR0cHM6Ly82ODAwLTE3OC0yMjUtMTM0LTIxNS5uZ3Jvay1mcmVlLmFwcC9hc3NldHMvY3JlZGVudGlhbHMvd2Vyb19iYWNrZ3JvdW5kLmpwZWcifX1dfSwiY3JlZGVudGlhbF9tZXRhZGF0YV91cmkiOiJodHRwczovLzY4MDAtMTc4LTIyNS0xMzQtMjE1Lm5ncm9rLWZyZWUuYXBwL3BheW1lbnQtY3JlZGVudGlhbC1tZXRhZGF0YSJ9LCJ3ZXJvLWNhcmQtc2Qtand0LWtleS1hdHRlc3RhdGlvbnMiOnsiZm9ybWF0IjoiZGMrc2Qtand0IiwidmN0IjoiZXUuZXVyb3BhLndlcm8uY2FyZCIsInNjb3BlIjoid2Vyby1jYXJkLXNkLWp3dCIsImNyeXB0b2dyYXBoaWNfYmluZGluZ19tZXRob2RzX3N1cHBvcnRlZCI6WyJqd2siXSwiY3JlZGVudGlhbF9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVkRFNBIiwiRVMyNTYiXSwicHJvb2ZfdHlwZXNfc3VwcG9ydGVkIjp7Imp3dCI6eyJwcm9vZl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkVTMjU2Il0sImtleV9hdHRlc3RhdGlvbnNfcmVxdWlyZWQiOnsidXNlcl9hdXRoZW50aWNhdGlvbiI6WyJpc29fMTgwNDVfaGlnaCJdLCJrZXlfc3RvcmFnZSI6WyJpc29fMTgwNDVfaGlnaCJdfX0sImF0dGVzdGF0aW9uIjp7InByb29mX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXSwia2V5X2F0dGVzdGF0aW9uc19yZXF1aXJlZCI6eyJ1c2VyX2F1dGhlbnRpY2F0aW9uIjpbImlzb18xODA0NV9oaWdoIl0sImtleV9zdG9yYWdlIjpbImlzb18xODA0NV9oaWdoIl19fX0sImRpc3BsYXkiOlt7ImxvY2FsZSI6ImVuIiwibmFtZSI6Ildlcm8gQmFuayBBY2NvdW50IiwidGV4dF9jb2xvciI6IiMxRDFDMUMiLCJiYWNrZ3JvdW5kX2NvbG9yIjoiI2ZmZjQ4ZCIsImJhY2tncm91bmRfaW1hZ2UiOnsidXJpIjoiaHR0cHM6Ly82ODAwLTE3OC0yMjUtMTM0LTIxNS5uZ3Jvay1mcmVlLmFwcC9hc3NldHMvY3JlZGVudGlhbHMvd2Vyb19iYWNrZ3JvdW5kLmpwZWciLCJ1cmwiOiJodHRwczovLzY4MDAtMTc4LTIyNS0xMzQtMjE1Lm5ncm9rLWZyZWUuYXBwL2Fzc2V0cy9jcmVkZW50aWFscy93ZXJvX2JhY2tncm91bmQuanBlZyJ9fV0sImNyZWRlbnRpYWxfbWV0YWRhdGEiOnsiZGlzcGxheSI6W3sibG9jYWxlIjoiZW4iLCJuYW1lIjoiV2VybyBCYW5rIEFjY291bnQiLCJ0ZXh0X2NvbG9yIjoiIzFEMUMxQyIsImJhY2tncm91bmRfY29sb3IiOiIjZmZmNDhkIiwiYmFja2dyb3VuZF9pbWFnZSI6eyJ1cmkiOiJodHRwczovLzY4MDAtMTc4LTIyNS0xMzQtMjE1Lm5ncm9rLWZyZWUuYXBwL2Fzc2V0cy9jcmVkZW50aWFscy93ZXJvX2JhY2tncm91bmQuanBlZyIsInVybCI6Imh0dHBzOi8vNjgwMC0xNzgtMjI1LTEzNC0yMTUubmdyb2stZnJlZS5hcHAvYXNzZXRzL2NyZWRlbnRpYWxzL3dlcm9fYmFja2dyb3VuZC5qcGVnIn19XX0sImNyZWRlbnRpYWxfbWV0YWRhdGFfdXJpIjoiaHR0cHM6Ly82ODAwLTE3OC0yMjUtMTM0LTIxNS5uZ3Jvay1mcmVlLmFwcC9wYXltZW50LWNyZWRlbnRpYWwtbWV0YWRhdGEifSwid2Vyby1jYXJkLXRoaXJkLXBhcnR5LXNkLWp3dCI6eyJmb3JtYXQiOiJkYytzZC1qd3QiLCJ2Y3QiOiJldS5ldXJvcGEud2Vyby5jYXJkLnRoaXJkLnBhcnR5Iiwic2NvcGUiOiJ3ZXJvLWNhcmQtdGhpcmQtcGFydHktc2Qtand0IiwiY3J5cHRvZ3JhcGhpY19iaW5kaW5nX21ldGhvZHNfc3VwcG9ydGVkIjpbImp3ayJdLCJjcmVkZW50aWFsX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRWREU0EiLCJFUzI1NiJdLCJwcm9vZl90eXBlc19zdXBwb3J0ZWQiOnsiand0Ijp7InByb29mX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiLCJFZERTQSJdfX0sImRpc3BsYXkiOlt7ImxvY2FsZSI6ImVuIiwibmFtZSI6Ildlcm8gQmFuayBBY2NvdW50IChUaGlyZCBQYXJ0eSkiLCJ0ZXh0X2NvbG9yIjoiIzFEMUMxQyIsImJhY2tncm91bmRfY29sb3IiOiIjZmZmNDhkIiwiYmFja2dyb3VuZF9pbWFnZSI6eyJ1cmkiOiJodHRwczovLzY4MDAtMTc4LTIyNS0xMzQtMjE1Lm5ncm9rLWZyZWUuYXBwL2Fzc2V0cy9jcmVkZW50aWFscy93ZXJvX2JhY2tncm91bmQuanBlZyIsInVybCI6Imh0dHBzOi8vNjgwMC0xNzgtMjI1LTEzNC0yMTUubmdyb2stZnJlZS5hcHAvYXNzZXRzL2NyZWRlbnRpYWxzL3dlcm9fYmFja2dyb3VuZC5qcGVnIn19XSwiY3JlZGVudGlhbF9tZXRhZGF0YSI6eyJkaXNwbGF5IjpbeyJsb2NhbGUiOiJlbiIsIm5hbWUiOiJXZXJvIEJhbmsgQWNjb3VudCAoVGhpcmQgUGFydHkpIiwidGV4dF9jb2xvciI6IiMxRDFDMUMiLCJiYWNrZ3JvdW5kX2NvbG9yIjoiI2ZmZjQ4ZCIsImJhY2tncm91bmRfaW1hZ2UiOnsidXJpIjoiaHR0cHM6Ly82ODAwLTE3OC0yMjUtMTM0LTIxNS5uZ3Jvay1mcmVlLmFwcC9hc3NldHMvY3JlZGVudGlhbHMvd2Vyb19iYWNrZ3JvdW5kLmpwZWciLCJ1cmwiOiJodHRwczovLzY4MDAtMTc4LTIyNS0xMzQtMjE1Lm5ncm9rLWZyZWUuYXBwL2Fzc2V0cy9jcmVkZW50aWFscy93ZXJvX2JhY2tncm91bmQuanBlZyJ9fV19LCJjcmVkZW50aWFsX21ldGFkYXRhX3VyaSI6Imh0dHBzOi8vNjgwMC0xNzgtMjI1LTEzNC0yMTUubmdyb2stZnJlZS5hcHAvcGF5bWVudC1jcmVkZW50aWFsLW1ldGFkYXRhIn0sIndlcm8tY2FyZC10aGlyZC1wYXJ0eS1zZC1qd3Qta2V5LWF0dGVzdGF0aW9ucyI6eyJmb3JtYXQiOiJkYytzZC1qd3QiLCJ2Y3QiOiJldS5ldXJvcGEud2Vyby5jYXJkLnRoaXJkLnBhcnR5Iiwic2NvcGUiOiJ3ZXJvLWNhcmQtdGhpcmQtcGFydHktc2Qtand0IiwiY3J5cHRvZ3JhcGhpY19iaW5kaW5nX21ldGhvZHNfc3VwcG9ydGVkIjpbImp3ayJdLCJjcmVkZW50aWFsX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRWREU0EiLCJFUzI1NiJdLCJwcm9vZl90eXBlc19zdXBwb3J0ZWQiOnsiand0Ijp7InByb29mX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiRVMyNTYiXSwia2V5X2F0dGVzdGF0aW9uc19yZXF1aXJlZCI6eyJ1c2VyX2F1dGhlbnRpY2F0aW9uIjpbImlzb18xODA0NV9oaWdoIl0sImtleV9zdG9yYWdlIjpbImlzb18xODA0NV9oaWdoIl19fSwiYXR0ZXN0YXRpb24iOnsicHJvb2Zfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJFUzI1NiJdLCJrZXlfYXR0ZXN0YXRpb25zX3JlcXVpcmVkIjp7InVzZXJfYXV0aGVudGljYXRpb24iOlsiaXNvXzE4MDQ1X2hpZ2giXSwia2V5X3N0b3JhZ2UiOlsiaXNvXzE4MDQ1X2hpZ2giXX19fSwiZGlzcGxheSI6W3sibG9jYWxlIjoiZW4iLCJuYW1lIjoiV2VybyBCYW5rIEFjY291bnQgKFRoaXJkIFBhcnR5KSIsInRleHRfY29sb3IiOiIjMUQxQzFDIiwiYmFja2dyb3VuZF9jb2xvciI6IiNmZmY0OGQiLCJiYWNrZ3JvdW5kX2ltYWdlIjp7InVyaSI6Imh0dHBzOi8vNjgwMC0xNzgtMjI1LTEzNC0yMTUubmdyb2stZnJlZS5hcHAvYXNzZXRzL2NyZWRlbnRpYWxzL3dlcm9fYmFja2dyb3VuZC5qcGVnIiwidXJsIjoiaHR0cHM6Ly82ODAwLTE3OC0yMjUtMTM0LTIxNS5uZ3Jvay1mcmVlLmFwcC9hc3NldHMvY3JlZGVudGlhbHMvd2Vyb19iYWNrZ3JvdW5kLmpwZWcifX1dLCJjcmVkZW50aWFsX21ldGFkYXRhIjp7ImRpc3BsYXkiOlt7ImxvY2FsZSI6ImVuIiwibmFtZSI6Ildlcm8gQmFuayBBY2NvdW50IChUaGlyZCBQYXJ0eSkiLCJ0ZXh0X2NvbG9yIjoiIzFEMUMxQyIsImJhY2tncm91bmRfY29sb3IiOiIjZmZmNDhkIiwiYmFja2dyb3VuZF9pbWFnZSI6eyJ1cmkiOiJodHRwczovLzY4MDAtMTc4LTIyNS0xMzQtMjE1Lm5ncm9rLWZyZWUuYXBwL2Fzc2V0cy9jcmVkZW50aWFscy93ZXJvX2JhY2tncm91bmQuanBlZyIsInVybCI6Imh0dHBzOi8vNjgwMC0xNzgtMjI1LTEzNC0yMTUubmdyb2stZnJlZS5hcHAvYXNzZXRzL2NyZWRlbnRpYWxzL3dlcm9fYmFja2dyb3VuZC5qcGVnIn19XX0sImNyZWRlbnRpYWxfbWV0YWRhdGFfdXJpIjoiaHR0cHM6Ly82ODAwLTE3OC0yMjUtMTM0LTIxNS5uZ3Jvay1mcmVlLmFwcC9wYXltZW50LWNyZWRlbnRpYWwtbWV0YWRhdGEifX0sImRpc3BsYXkiOlt7Im5hbWUiOiJwYXkuZXhhbXBsZSBQYXltZW50IENyZWRlbnRpYWwiLCJsb2NhbGUiOiJlbiJ9XSwibm9uY2VfZW5kcG9pbnQiOiJodHRwczovLzY4MDAtMTc4LTIyNS0xMzQtMjE1Lm5ncm9rLWZyZWUuYXBwL29pZDR2Y2kvN2NjMDI4YTMtOGNlMi00MzJhLWJmMTktNTYyMTA2ODU4NmRmL25vbmNlIiwidHJhbnNhY3Rpb25fZGF0YV90eXBlcyI6eyJ1cm46ZXVkaTpzY2E6ZXUuZXVyb3BhLmVjOnBheW1lbnQ6c2luZ2xlOjEiOnsiY2xhaW1zIjpbeyJwYXRoIjpbInRyYW5zYWN0aW9uX2lkIl0sIm1hbmRhdG9yeSI6dHJ1ZX0seyJwYXRoIjpbImRhdGVfdGltZSJdLCJ2YWx1ZV90eXBlIjoiaXNvX2RhdGVfdGltZSIsImRpc3BsYXkiOlt7ImxvY2FsZSI6ImRlLURFIiwibmFtZSI6IkRhdHVtIn0seyJsb2NhbGUiOiJlbi1HQiIsIm5hbWUiOiJEYXRlIn1dfSx7InBhdGgiOlsiYW1vdW50Il0sIm1hbmRhdG9yeSI6dHJ1ZSwidmFsdWVfdHlwZSI6Imlzb19jdXJyZW5jeV9hbW91bnQiLCJkaXNwbGF5IjpbeyJsb2NhbGUiOiJkZS1ERSIsIm5hbWUiOiJCZXRyYWcifSx7ImxvY2FsZSI6ImVuLUdCIiwibmFtZSI6IkFtb3VudCJ9XX0seyJwYXRoIjpbInBheWVlIiwibmFtZSJdLCJtYW5kYXRvcnkiOnRydWUsImRpc3BsYXkiOlt7ImxvY2FsZSI6ImRlLURFIiwibmFtZSI6IkVtcGbDpG5nZXIifSx7ImxvY2FsZSI6ImVuLUdCIiwibmFtZSI6IlBheWVlIn1dfSx7InBhdGgiOlsicGF5ZWUiLCJpZCJdLCJtYW5kYXRvcnkiOnRydWV9XSwidWlfbGFiZWxzIjp7ImFmZmlybWF0aXZlX2FjdGlvbl9sYWJlbCI6W3sibG9jYWxlIjoiZGUtREUiLCJ2YWx1ZSI6IlphaGx1bmcgYmVzdMOkdGlnZW4ifSx7ImxvY2FsZSI6ImVuLUdCIiwidmFsdWUiOiJDb25maXJtIFBheW1lbnQifV19fX19LCJpc3MiOiI3Y2MwMjhhMy04Y2UyLTQzMmEtYmYxOS01NjIxMDY4NTg2ZGYiLCJzdWIiOiJ2Y3QiLCJleHAiOjE4NzAzNTI5NDgsImlhdCI6MTc3NTY1ODU0OH0.0ue9jE3tuQdvZTl2q8kJXuK5ypW42E_GH5vXi0WvLKRBmtbbhRmuXe5gP8NYyWtG7yrHZm1YybnJEPXskcobwA'

suite('fetch credential metadata', () => {
  const server = setupServer(
    http.get('https://6800-178-225-134-215.ngrok-free.app/payments-credential-metadata', () =>
      HttpResponse.text(credentialMetadataJwt)
    )
  )
  beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
  afterAll(() => server.close())

  test('fetch valid credential metadata', async () => {
    const metadata = await fetchCredentialMetadata(
      async () => {},
      'https://6800-178-225-134-215.ngrok-free.app/payments-credential-metadata'
    )
    expect(metadata).toMatchObject({
      credential_configurations_supported: {
        'wero-card-sd-jwt': {
          credential_metadata: {
            display: [
              {
                background_color: '#fff48d',
                background_image: {
                  uri: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
                  url: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
                },
                locale: 'en',
                name: 'Wero Bank Account',
                text_color: '#1D1C1C',
              },
            ],
          },
          credential_metadata_uri: 'https://6800-178-225-134-215.ngrok-free.app/payment-credential-metadata',
          credential_signing_alg_values_supported: ['EdDSA', 'ES256'],
          cryptographic_binding_methods_supported: ['jwk'],
          display: [
            {
              background_color: '#fff48d',
              background_image: {
                uri: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
                url: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
              },
              locale: 'en',
              name: 'Wero Bank Account',
              text_color: '#1D1C1C',
            },
          ],
          format: 'dc+sd-jwt',
          proof_types_supported: {
            jwt: {
              proof_signing_alg_values_supported: ['ES256', 'EdDSA'],
            },
          },
          scope: 'wero-card-sd-jwt',
          vct: 'eu.europa.wero.card',
        },
        'wero-card-sd-jwt-key-attestations': {
          credential_metadata: {
            display: [
              {
                background_color: '#fff48d',
                background_image: {
                  uri: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
                  url: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
                },
                locale: 'en',
                name: 'Wero Bank Account',
                text_color: '#1D1C1C',
              },
            ],
          },
          credential_metadata_uri: 'https://6800-178-225-134-215.ngrok-free.app/payment-credential-metadata',
          credential_signing_alg_values_supported: ['EdDSA', 'ES256'],
          cryptographic_binding_methods_supported: ['jwk'],
          display: [
            {
              background_color: '#fff48d',
              background_image: {
                uri: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
                url: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
              },
              locale: 'en',
              name: 'Wero Bank Account',
              text_color: '#1D1C1C',
            },
          ],
          format: 'dc+sd-jwt',
          proof_types_supported: {
            attestation: {
              key_attestations_required: {
                key_storage: ['iso_18045_high'],
                user_authentication: ['iso_18045_high'],
              },
              proof_signing_alg_values_supported: ['ES256'],
            },
            jwt: {
              key_attestations_required: {
                key_storage: ['iso_18045_high'],
                user_authentication: ['iso_18045_high'],
              },
              proof_signing_alg_values_supported: ['ES256'],
            },
          },
          scope: 'wero-card-sd-jwt',
          vct: 'eu.europa.wero.card',
        },
        'wero-card-third-party-sd-jwt': {
          credential_metadata: {
            display: [
              {
                background_color: '#fff48d',
                background_image: {
                  uri: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
                  url: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
                },
                locale: 'en',
                name: 'Wero Bank Account (Third Party)',
                text_color: '#1D1C1C',
              },
            ],
          },
          credential_metadata_uri: 'https://6800-178-225-134-215.ngrok-free.app/payment-credential-metadata',
          credential_signing_alg_values_supported: ['EdDSA', 'ES256'],
          cryptographic_binding_methods_supported: ['jwk'],
          display: [
            {
              background_color: '#fff48d',
              background_image: {
                uri: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
                url: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
              },
              locale: 'en',
              name: 'Wero Bank Account (Third Party)',
              text_color: '#1D1C1C',
            },
          ],
          format: 'dc+sd-jwt',
          proof_types_supported: {
            jwt: {
              proof_signing_alg_values_supported: ['ES256', 'EdDSA'],
            },
          },
          scope: 'wero-card-third-party-sd-jwt',
          vct: 'eu.europa.wero.card.third.party',
        },
        'wero-card-third-party-sd-jwt-key-attestations': {
          credential_metadata: {
            display: [
              {
                background_color: '#fff48d',
                background_image: {
                  uri: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
                  url: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
                },
                locale: 'en',
                name: 'Wero Bank Account (Third Party)',
                text_color: '#1D1C1C',
              },
            ],
          },
          credential_metadata_uri: 'https://6800-178-225-134-215.ngrok-free.app/payment-credential-metadata',
          credential_signing_alg_values_supported: ['EdDSA', 'ES256'],
          cryptographic_binding_methods_supported: ['jwk'],
          display: [
            {
              background_color: '#fff48d',
              background_image: {
                uri: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
                url: 'https://6800-178-225-134-215.ngrok-free.app/assets/credentials/wero_background.jpeg',
              },
              locale: 'en',
              name: 'Wero Bank Account (Third Party)',
              text_color: '#1D1C1C',
            },
          ],
          format: 'dc+sd-jwt',
          proof_types_supported: {
            attestation: {
              key_attestations_required: {
                key_storage: ['iso_18045_high'],
                user_authentication: ['iso_18045_high'],
              },
              proof_signing_alg_values_supported: ['ES256'],
            },
            jwt: {
              key_attestations_required: {
                key_storage: ['iso_18045_high'],
                user_authentication: ['iso_18045_high'],
              },
              proof_signing_alg_values_supported: ['ES256'],
            },
          },
          scope: 'wero-card-third-party-sd-jwt',
          vct: 'eu.europa.wero.card.third.party',
        },
      },
      credential_endpoint:
        'https://6800-178-225-134-215.ngrok-free.app/oid4vci/7cc028a3-8ce2-432a-bf19-5621068586df/credential',
      credential_issuer: 'https://6800-178-225-134-215.ngrok-free.app/oid4vci/7cc028a3-8ce2-432a-bf19-5621068586df',
      deferred_credential_endpoint:
        'https://6800-178-225-134-215.ngrok-free.app/oid4vci/7cc028a3-8ce2-432a-bf19-5621068586df/deferred-credential',
      display: [
        {
          locale: 'en',
          name: 'pay.example Payment Credential',
        },
      ],
      nonce_endpoint: 'https://6800-178-225-134-215.ngrok-free.app/oid4vci/7cc028a3-8ce2-432a-bf19-5621068586df/nonce',
      transaction_data_types: {
        'urn:eudi:sca:eu.europa.ec:payment:single:1': {
          claims: [
            {
              mandatory: true,
              path: ['transaction_id'],
            },
            {
              display: [
                {
                  locale: 'de-DE',
                  name: 'Datum',
                },
                {
                  locale: 'en-GB',
                  name: 'Date',
                },
              ],
              path: ['date_time'],
              value_type: 'iso_date_time',
            },
            {
              display: [
                {
                  locale: 'de-DE',
                  name: 'Betrag',
                },
                {
                  locale: 'en-GB',
                  name: 'Amount',
                },
              ],
              mandatory: true,
              path: ['amount'],
              value_type: 'iso_currency_amount',
            },
            {
              display: [
                {
                  locale: 'de-DE',
                  name: 'Empfänger',
                },
                {
                  locale: 'en-GB',
                  name: 'Payee',
                },
              ],
              mandatory: true,
              path: ['payee', 'name'],
            },
            {
              mandatory: true,
              path: ['payee', 'id'],
            },
          ],
          ui_labels: {
            affirmative_action_label: [
              {
                locale: 'de-DE',
                value: 'Zahlung bestätigen',
              },
              {
                locale: 'en-GB',
                value: 'Confirm Payment',
              },
            ],
          },
        },
      },
    })
  })
})
