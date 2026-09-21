export function parseName(value) { return value.trim(); }
export class Registry { find(name) { return parseName(name); } }
