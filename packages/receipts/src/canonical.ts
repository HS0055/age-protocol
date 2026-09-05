// RFC 8785 JSON Canonicalization Scheme. JSON.stringify already serializes
// numbers and strings the way JCS requires; what it lacks is deterministic
// key order, which sortKeysDeep supplies.
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

// A verifier is handed JSON by strangers, and recursion on attacker-chosen
// nesting is a stack overflow waiting to happen. No honest AGE document comes
// close to this depth, so exceeding it is a rejection, not a crash.
export const MAX_DEPTH = 64;

function sortKeysDeep(value: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH) {
    throw new RangeError(`canonicalize: nesting deeper than ${MAX_DEPTH} levels`);
  }
  if (Array.isArray(value)) return value.map((item) => sortKeysDeep(item, depth + 1));
  if (value !== null && typeof value === 'object') {
    const source = value as Record<string, unknown>;
    // A null prototype keeps a member named __proto__ an own property instead
    // of letting the assignment below set the prototype and drop the member.
    const out = Object.create(null) as Record<string, unknown>;
    for (const key of Object.keys(source).sort()) {
      const item = source[key];
      if (item === undefined) continue;
      out[key] = sortKeysDeep(item, depth + 1);
    }
    return out;
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new TypeError('canonicalize: non-finite number cannot be represented in JSON');
  }
  return value;
}
