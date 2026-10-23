export enum MetadataMergeStrategy {
  /**
   *
   * Allowed only when the operator values are equal. If not, this MUST result in a policy error.
   *
   */
  OperatorValuesEqual = 0,
  /**
   *
   * The result of merging the values of two these operators is the union of the operator values.
   *
   */
  Union = 1,
  /**
   *
   * The result of merging the values of two these operators is the intersection of the operator values. If the intersection is empty, this MUST result in a policy error.
   *
   */
  Intersection = 2,
  /**
   *
   * The result of merging the values of two these operators is the logical disjunction (OR) of the operator values.
   *
   */
  LogicalOr = 3,
  /**
   *
   * The result of merging the values of two these operators is the intersection of the operator values. The intersection may be an empty array.
   *
   */
  IntersectionMayBeEmpty = 4,
}
