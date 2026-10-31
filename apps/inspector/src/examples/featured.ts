// Made by scripts/generate-examples.mjs, run `pnpm --filter identity-inspector examples` to make it again
import type { FeaturedExample } from '../example'

export const featured: FeaturedExample[] = [
  {
    page: 'sd-jwt',
    id: 'pid-presentation',
    title: 'PID presentation',
  },
  {
    page: 'over-asking',
    id: 'asks-for-more',
    title: 'Asks for more',
  },
  {
    page: 'trusted-list',
    id: 'eu-lotl',
    title: 'EU List of Trusted Lists',
  },
  {
    page: 'status-list',
    id: 'revoked-and-suspended',
    title: 'Revoked and suspended tokens',
  },
  {
    page: 'registration-certificate',
    id: 'for-another-relying-party',
    title: 'For another relying party',
  },
  {
    page: 'mdoc',
    id: 'mdl',
    title: 'mDL',
  },
]
