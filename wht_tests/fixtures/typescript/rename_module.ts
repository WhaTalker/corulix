export function computeLabel(value: string): string {
  return value.trim();
}

export function unrelatedDecoyHolder(): string {
  const computeLabel = "shadowed-local-not-the-real-symbol";
  return computeLabel;
}
