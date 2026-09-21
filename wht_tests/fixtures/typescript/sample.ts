export interface ParserResult { ok: boolean }
export function parseName(value: string): string { return value.trim(); }
export class Registry { find(name: string) { return parseName(name); } }
