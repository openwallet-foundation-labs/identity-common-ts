// Made by scripts/generate-examples.mjs, run `pnpm --filter identity-inspector examples` to make it again
import type { Example } from '../example'

export const examples: Example[] = [
  {
    id: 'within-the-registration',
    title: 'Within the registration',
    description:
      'An authorization request for the names of a PID, which the registration certificate in its verifier_info registers.',
    values: {
      request:
        '{\n  "response_type": "vp_token",\n  "client_id": "x509_san_dns:verifier.example",\n  "nonce": "n-0S6_WzA2Mj",\n  "dcql_query": {\n    "credentials": [\n      {\n        "id": "pid",\n        "format": "dc+sd-jwt",\n        "meta": {\n          "vct_values": [\n            "urn:eudi:pid:1"\n          ]\n        },\n        "claims": [\n          {\n            "path": [\n              "given_name"\n            ]\n          },\n          {\n            "path": [\n              "family_name"\n            ]\n          }\n        ]\n      }\n    ]\n  },\n  "verifier_info": [\n    {\n      "format": "jwt",\n      "data": "eyJhbGciOiJFUzI1NiIsInR5cCI6InJjLXdycCtqd3QiLCJ4NWMiOlsiTUlJQjl6Q0NBWnlnQXdJQkFnSUNFQU13Q2dZSUtvWkl6ajBFQXdJd2F6RUxNQWtHQTFVRUJoTUNSRVV4SXpBaEJnTlZCQW9NR2tWNFlXMXdiR1VnUVdOalpYTnpJRU5CSUZCeWIzWnBaR1Z5TVJjd0ZRWURWUVJoREE1T1ZGSkVSUzFJVWtJeE1qTTBOVEVlTUJ3R0ExVUVBd3dWUlhoaGJYQnNaU0JYVWxBZ1FXTmpaWE56SUVOQk1CNFhEVEkyTVRBek1ERXhOVEEwTmxvWERUTTJNRGt3TVRBd01EQXdNRm93T3pFTE1Ba0dBMVVFQmhNQ1JFVXhFREFPQmdOVkJBb01CMFY0WVcxd2JHVXhHakFZQmdOVkJBTU1FVVY0WVcxd2JHVWdVbVZuYVhOMGNtRnlNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVia205Qy9kSmE4UXhOUFBmSXlBNGlhTG1sZi9JZ0VtM1VhUWFFTm5GSm9zc3ZLMmJYaXFQTHlpcHcwWFlVQWhnMmxSbmk0SGVva1Jhb0JBbmUyU2JHYU5nTUY0d0RBWURWUjBUQVFIL0JBSXdBREFPQmdOVkhROEJBZjhFQkFNQ0I0QXdIUVlEVlIwT0JCWUVGTTF1Q1UrSjAza08xQzVYVk1VaitxL2ZMSkxYTUI4R0ExVWRJd1FZTUJhQUZIWGRITE9lais4M3g3K0hpTDRmckJwdjF6MzVNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUURBOWpzWjhXRm8zKyt5dHdUbCtUaFo5cHcyc2kyS25xQkswdWlyMjd5ZktBSWhBS3BzSFRzTmRSMnhHMnhia3dpSWJjSGZlMHdxYjFKRW45YTJJTTVDR0tOaiJdLCJpYXQiOjE3OTM0NDc0NDZ9.eyJuYW1lIjoiRXhhbXBsZSBTaG9wIiwic3ViX2xuIjoiRXhhbXBsZSBTaG9wIEdtYkgiLCJzdWIiOiJWQVRERS0xMjM0NTY3ODkiLCJjb3VudHJ5IjoiREUiLCJyZWdpc3RyeV91cmkiOiJodHRwczovL3JlZ2lzdHJhci5leGFtcGxlL3dycCIsImVudGl0bGVtZW50cyI6WyJodHRwczovL3VyaS5ldHNpLm9yZy8xOTQ3NS9FbnRpdGxlbWVudC9TZXJ2aWNlX1Byb3ZpZGVyIl0sImlhdCI6MTc5MzQ0NzQ0NiwicHVycG9zZSI6W3sibGFuZyI6ImVuIiwidmFsdWUiOiJBZ2UgdmVyaWZpY2F0aW9uIGF0IGNoZWNrb3V0In1dLCJjcmVkZW50aWFscyI6W3siZm9ybWF0IjoiZGMrc2Qtand0IiwibWV0YSI6eyJ2Y3RfdmFsdWVzIjpbInVybjpldWRpOnBpZDoxIl19LCJjbGFpbSI6W3sicGF0aCI6WyJnaXZlbl9uYW1lIl19LHsicGF0aCI6WyJmYW1pbHlfbmFtZSJdfV19XX0.0ScuI4aG_DfAwk5oX9sCnKh4JOsbobvIqL7aOFe_2IQCJag6IxhdNoqMEQ5ZEUK9alqR6O61AFiL9KRaszZzjw"\n    }\n  ]\n}',
    },
    expect: {
      findings: [],
      signatures: [],
    },
  },
  {
    id: 'asks-for-more',
    title: 'Asks for more',
    description:
      'The same relying party also asks for the birthdate of the PID and for an mDL, neither of which it registered.',
    values: {
      request:
        '{\n  "response_type": "vp_token",\n  "client_id": "x509_san_dns:verifier.example",\n  "nonce": "n-0S6_WzA2Mj",\n  "dcql_query": {\n    "credentials": [\n      {\n        "id": "pid",\n        "format": "dc+sd-jwt",\n        "meta": {\n          "vct_values": [\n            "urn:eudi:pid:1"\n          ]\n        },\n        "claims": [\n          {\n            "path": [\n              "given_name"\n            ]\n          },\n          {\n            "path": [\n              "family_name"\n            ]\n          },\n          {\n            "path": [\n              "birthdate"\n            ]\n          }\n        ]\n      },\n      {\n        "id": "mdl",\n        "format": "mso_mdoc",\n        "meta": {\n          "doctype_value": "org.iso.18013.5.1.mDL"\n        },\n        "claims": [\n          {\n            "path": [\n              "org.iso.18013.5.1",\n              "driving_privileges"\n            ]\n          }\n        ]\n      }\n    ]\n  },\n  "verifier_info": [\n    {\n      "format": "jwt",\n      "data": "eyJhbGciOiJFUzI1NiIsInR5cCI6InJjLXdycCtqd3QiLCJ4NWMiOlsiTUlJQjl6Q0NBWnlnQXdJQkFnSUNFQU13Q2dZSUtvWkl6ajBFQXdJd2F6RUxNQWtHQTFVRUJoTUNSRVV4SXpBaEJnTlZCQW9NR2tWNFlXMXdiR1VnUVdOalpYTnpJRU5CSUZCeWIzWnBaR1Z5TVJjd0ZRWURWUVJoREE1T1ZGSkVSUzFJVWtJeE1qTTBOVEVlTUJ3R0ExVUVBd3dWUlhoaGJYQnNaU0JYVWxBZ1FXTmpaWE56SUVOQk1CNFhEVEkyTVRBek1ERXhOVEEwTmxvWERUTTJNRGt3TVRBd01EQXdNRm93T3pFTE1Ba0dBMVVFQmhNQ1JFVXhFREFPQmdOVkJBb01CMFY0WVcxd2JHVXhHakFZQmdOVkJBTU1FVVY0WVcxd2JHVWdVbVZuYVhOMGNtRnlNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVia205Qy9kSmE4UXhOUFBmSXlBNGlhTG1sZi9JZ0VtM1VhUWFFTm5GSm9zc3ZLMmJYaXFQTHlpcHcwWFlVQWhnMmxSbmk0SGVva1Jhb0JBbmUyU2JHYU5nTUY0d0RBWURWUjBUQVFIL0JBSXdBREFPQmdOVkhROEJBZjhFQkFNQ0I0QXdIUVlEVlIwT0JCWUVGTTF1Q1UrSjAza08xQzVYVk1VaitxL2ZMSkxYTUI4R0ExVWRJd1FZTUJhQUZIWGRITE9lais4M3g3K0hpTDRmckJwdjF6MzVNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUURBOWpzWjhXRm8zKyt5dHdUbCtUaFo5cHcyc2kyS25xQkswdWlyMjd5ZktBSWhBS3BzSFRzTmRSMnhHMnhia3dpSWJjSGZlMHdxYjFKRW45YTJJTTVDR0tOaiJdLCJpYXQiOjE3OTM0NDc0NDZ9.eyJuYW1lIjoiRXhhbXBsZSBTaG9wIiwic3ViX2xuIjoiRXhhbXBsZSBTaG9wIEdtYkgiLCJzdWIiOiJWQVRERS0xMjM0NTY3ODkiLCJjb3VudHJ5IjoiREUiLCJyZWdpc3RyeV91cmkiOiJodHRwczovL3JlZ2lzdHJhci5leGFtcGxlL3dycCIsImVudGl0bGVtZW50cyI6WyJodHRwczovL3VyaS5ldHNpLm9yZy8xOTQ3NS9FbnRpdGxlbWVudC9TZXJ2aWNlX1Byb3ZpZGVyIl0sImlhdCI6MTc5MzQ0NzQ0NiwicHVycG9zZSI6W3sibGFuZyI6ImVuIiwidmFsdWUiOiJBZ2UgdmVyaWZpY2F0aW9uIGF0IGNoZWNrb3V0In1dLCJjcmVkZW50aWFscyI6W3siZm9ybWF0IjoiZGMrc2Qtand0IiwibWV0YSI6eyJ2Y3RfdmFsdWVzIjpbInVybjpldWRpOnBpZDoxIl19LCJjbGFpbSI6W3sicGF0aCI6WyJnaXZlbl9uYW1lIl19LHsicGF0aCI6WyJmYW1pbHlfbmFtZSJdfV19XX0.0ScuI4aG_DfAwk5oX9sCnKh4JOsbobvIqL7aOFe_2IQCJag6IxhdNoqMEQ5ZEUK9alqR6O61AFiL9KRaszZzjw"\n    }\n  ]\n}',
    },
    expect: {
      findings: ['claim_not_registered', 'credential_not_registered'],
      signatures: [],
    },
  },
]
