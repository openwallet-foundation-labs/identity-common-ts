import { z } from 'zod'
import { DcqlParseError } from '../dcql-error/e-dcql.js'
import type { DcqlClaimsQuery } from '../dcql-query/m-dcql-claims-query.js'
import type { DcqlCredentialQuery } from '../dcql-query/m-dcql-credential-query.js'
import type { DcqlClaimsResult } from '../dcql-query-result/m-claims-result.js'
import {
  addDcqlIssue,
  asNonEmptyArrayOrUndefined,
  DCQL_VALIDATION_CODES,
  DcqlNotDisclosed,
  isNonEmptyArray,
  isObject,
  parseDcql,
  type ToNonEmptyArray,
  zMatch,
} from '../u-dcql.js'
import type { DcqlCredential } from '../u-dcql-credential.js'
import { deepMerge } from '../util/deep-merge.js'

const pathToString = (path: Array<string | null | number>) =>
  path.map((item) => (typeof item === 'string' ? `'${item}'` : `${item}`)).join('.')

const formatValue = (value: unknown) => (typeof value === 'string' ? `'${value}'` : `${String(value)}`)

// An issue of the parse of a nested value, re-added to the parse of the value it is in
const nestedIssue = (issue: z.core.$ZodIssue, path: PropertyKey[]) =>
  ({ ...issue, path: [...path, ...issue.path] }) as z.core.$ZodRawIssue

const claimsPathNotFound = (message: string) => () => ({ code: DCQL_VALIDATION_CODES.CLAIMS_PATH_NOT_FOUND, message })

// An object or array along the claims path pointer, which is missing when the value is of another type
const zClaimObject = (shape: z.core.$ZodShape, message: string) =>
  zMatch<Record<string, unknown>>(isObject, claimsPathNotFound(message)).pipe(z.object(shape))
const zClaimArray = (message: string) => zMatch<unknown[]>(Array.isArray, claimsPathNotFound(message))

const getClaimParser = (path: Array<string | number | null>, values?: DcqlClaimsQuery.ClaimValue[]) =>
  z.custom().superRefine((value, ctx) => {
    if (value === undefined || value === DcqlNotDisclosed) {
      addDcqlIssue(ctx, claimsPathNotFound(`Expected claim '${path.join("'.'")}' to be defined`)())
    } else if (values && !values.includes(value as DcqlClaimsQuery.ClaimValue)) {
      addDcqlIssue(ctx, {
        code: DCQL_VALIDATION_CODES.CLAIM_VALUES_MISMATCH,
        message: `Expected claim ${pathToString(path)} to be ${values.map(formatValue).join(' | ')} but received ${formatValue(value)}`,
        context: { expected: values, actual: value },
      })
    }
  })

export const getMdocClaimParser = (claimQuery: DcqlClaimsQuery.Mdoc) => {
  // Normalize the query to the latest path syntax
  const mdocPathQuery: DcqlClaimsQuery.MdocPath =
    'namespace' in claimQuery
      ? {
          id: claimQuery.id,
          path: [claimQuery.namespace, claimQuery.claim_name],
          values: claimQuery.values,
        }
      : claimQuery

  const namespace = mdocPathQuery.path[0]
  const field = mdocPathQuery.path[1]

  const message = `Expected claim ${pathToString(mdocPathQuery.path)} to be defined`
  return zClaimObject(
    { [namespace]: zClaimObject({ [field]: getClaimParser(mdocPathQuery.path, claimQuery.values) }, message) },
    message
  )
}

export const getJsonClaimParser = (
  claimQuery: DcqlClaimsQuery.W3cAndSdJwtVc,
  ctx: { index: number; presentation: boolean }
): z.ZodType => {
  const { index, presentation } = ctx
  const pathElement = claimQuery.path[index]
  const isLast = index === claimQuery.path.length - 1

  const claimParser = getClaimParser(claimQuery.path, claimQuery.values)
  const zArray = zClaimArray(`Expected path ${pathToString(claimQuery.path.slice(0, index + 1))} to be an array`)

  if (typeof pathElement === 'number') {
    const elementParser = isLast ? claimParser : getJsonClaimParser(claimQuery, { ...ctx, index: index + 1 })

    if (presentation) {
      return zArray.superRefine((value, ctx) => {
        const arrayPath = pathToString(claimQuery.path.slice(0, index + 1))
        const issues = []
        for (const [itemIndex, item] of value.entries()) {
          const itemResult = elementParser.safeParse(item, { reportInput: true })

          if (itemResult.success) return

          issues.push(nestedIssue(itemResult.error.issues[0], [itemIndex]))
        }

        if (!issues[0]) {
          addDcqlIssue(
            ctx,
            claimsPathNotFound(`Expected any element in array ${arrayPath} to match, but the array is empty`)()
          )
          return
        }

        ctx.addIssue({
          ...issues[0],
          message: isLast
            ? issues[0].message
            : `Expected any element in array ${arrayPath} to match sub requirement but none matched: ${issues[0].message}`,
        })
      })
    }

    return zArray.transform((value, payload) => {
      // Validate the specific element
      const result = elementParser.safeParse(value[pathElement], { reportInput: true })
      if (!result.success) {
        payload.issues.push(nestedIssue(result.error.issues[0], [pathElement]))
        return z.NEVER
      }

      // We need to preserve array ordering, so we add DcqlNotDisclosed elements for all items
      // before the current pathElement number
      return [...value.slice(0, pathElement).map(() => DcqlNotDisclosed), result.data]
    })
  }

  if (typeof pathElement === 'string') {
    return zClaimObject(
      { [pathElement]: isLast ? claimParser : getJsonClaimParser(claimQuery, { ...ctx, index: index + 1 }) },
      `Expected claim ${pathToString(claimQuery.path)} to be defined`
    )
  }

  const itemParser = isLast ? claimParser : getJsonClaimParser(claimQuery, { ...ctx, index: index + 1 })
  return zArray.transform((value, payload) => {
    const mapped = value.map((item) => itemParser.safeParse(item, { reportInput: true }))

    if (mapped.every((parsed) => !parsed.success)) {
      for (const [itemIndex, parsed] of mapped.entries()) {
        for (const issue of parsed.error?.issues ?? []) {
          payload.issues.push(nestedIssue(issue, [itemIndex]))
        }
      }

      return z.NEVER
    }

    return mapped.map((parsed) => (parsed.success ? parsed.data : DcqlNotDisclosed))
  })
}

export const runClaimsQuery = (
  credentialQuery: DcqlCredentialQuery,
  ctx: {
    credential: DcqlCredential
    presentation: boolean
  }
): DcqlClaimsResult => {
  // No claims, always matches
  if (!credentialQuery.claims) {
    return {
      success: true,
      valid_claims: undefined,
      failed_claims: undefined,
      valid_claim_sets: [
        {
          claim_set_index: undefined,
          output: {},
          success: true,
          valid_claim_indexes: undefined,
        },
      ],
      failed_claim_sets: undefined,
    }
  }

  const failedClaims: Array<z.output<typeof DcqlClaimsResult.zClaimsEntryFailureResult>> = []
  const validClaims: Array<z.output<typeof DcqlClaimsResult.zClaimsEntrySuccessResult>> = []

  for (const [claimIndex, claimQuery] of credentialQuery.claims.entries()) {
    const parser =
      credentialQuery.format === 'mso_mdoc'
        ? getMdocClaimParser(claimQuery as DcqlClaimsQuery.Mdoc)
        : getJsonClaimParser(claimQuery as DcqlClaimsQuery.W3cAndSdJwtVc, {
            index: 0,
            presentation: ctx.presentation,
          })

    const parseResult = parseDcql(
      parser,
      ctx.credential.credential_format === 'mso_mdoc' ? ctx.credential.namespaces : ctx.credential.claims
    )

    if (parseResult.success) {
      validClaims.push({
        success: true,
        claim_index: claimIndex,
        claim_id: claimQuery.id,
        output: parseResult.data as DcqlClaimsResult.ClaimsOutput,
      })
    } else {
      failedClaims.push({
        success: false,
        issues: parseResult.issues,
        claim_index: claimIndex,
        claim_id: claimQuery.id,
      })
    }
  }

  const failedClaimSets: z.output<typeof DcqlClaimsResult.zClaimSetFailureResult>[] = []
  const validClaimSets: z.output<typeof DcqlClaimsResult.zClaimSetSuccessResult>[] = []

  for (const [claimSetIndex, claimSet] of credentialQuery.claim_sets?.entries() ?? [[undefined, undefined]]) {
    const claims = claimSet?.map((id) => {
      const claim =
        validClaims.find((claim) => claim.claim_id === id) ?? failedClaims.find((claim) => claim.claim_id === id)
      if (!claim) {
        throw new DcqlParseError({
          message: `Claim with id '${id}' in query '${credentialQuery.id}' from claim set with index '${claimSetIndex}' not found in claims of claim`,
        })
      }

      return claim
    }) ?? [...validClaims, ...failedClaims] // This handles the case where there is no claim sets (so we use all claims)

    if (claims.every((claim) => claim.success)) {
      const output = claims.reduce((merged, claim) => deepMerge(claim.output, merged), {})
      validClaimSets.push({
        success: true,
        claim_set_index: claimSetIndex,
        output,
        valid_claim_indexes: asNonEmptyArrayOrUndefined(claims.map((claim) => claim.claim_index)),
      })
    } else {
      failedClaimSets.push({
        success: false,
        issues: claims.flatMap((claim) => (claim.success ? [] : claim.issues)),
        claim_set_index: claimSetIndex,
        failed_claim_indexes: claims.filter((claim) => !claim.success).map((claim) => claim.claim_index) as [
          number,
          ...number[],
        ],
        valid_claim_indexes: asNonEmptyArrayOrUndefined(
          claims.filter((claim) => claim.success).map((claim) => claim.claim_index)
        ),
      })
    }
  }

  if (isNonEmptyArray(validClaimSets)) {
    return {
      success: true,
      failed_claim_sets: asNonEmptyArrayOrUndefined(failedClaimSets),
      valid_claim_sets: validClaimSets,
      valid_claims: asNonEmptyArrayOrUndefined(validClaims),
      failed_claims: asNonEmptyArrayOrUndefined(failedClaims),
    }
  }

  // If valid claim sets is empty we know for sure there
  // is at least one failed claim and one failed claim set
  return {
    success: false,
    failed_claim_sets: failedClaimSets as ToNonEmptyArray<typeof failedClaimSets>,
    failed_claims: failedClaims as ToNonEmptyArray<typeof failedClaims>,
    valid_claims: asNonEmptyArrayOrUndefined(validClaims),
  }
}
