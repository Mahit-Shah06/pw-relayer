// Strip formatting spaces, including non-breaking spaces copied from contacts.
// Do not silently truncate digits or turn letters into a different number.
export function normalizePhone(value) {
  return typeof value === 'string' ? value.replace(/\s+/gu, '') : value;
}
