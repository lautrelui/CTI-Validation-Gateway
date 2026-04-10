/**
 * Identifier normalization per IVS spec section 4.10.
 * Each identifier type has specific normalization rules.
 */

function normalizeIdentifier(identifierType, rawValue, issuerCountry) {
  const notes = [];
  let normalized = rawValue;

  // General rules: trim, collapse spaces
  normalized = normalized.trim();
  if (normalized !== rawValue) notes.push('trimmed whitespace');

  switch (identifierType) {
    case 'NIU':
      normalized = normalizeNIU(normalized, notes);
      break;
    case 'PASSPORT':
      normalized = normalizePassport(normalized, notes);
      break;
    case 'NID':
      normalized = normalizeNID(normalized, issuerCountry, notes);
      break;
    case 'DRIVER_LICENSE':
      normalized = normalizeDriverLicense(normalized, issuerCountry, notes);
      break;
    default:
      // Fallback: basic normalization
      normalized = normalized.replace(/\s+/g, '');
      break;
  }

  return {
    normalized_value: normalized,
    normalization_version: 'v1',
    normalization_notes: notes.length > 0 ? notes : null,
  };
}

function normalizeNIU(value, notes) {
  // Remove spaces and dashes
  let result = value.replace(/[\s-]/g, '');
  if (result !== value.trim()) notes.push('removed separators');

  // NIU can be alphanumeric (e.g. P24000000544639E) — uppercase for consistency
  const uppercased = result.toUpperCase();
  if (uppercased !== result) notes.push('uppercased');
  result = uppercased;

  return result;
}

function normalizePassport(value, notes) {
  // Uppercase, remove spaces, preserve alphanumeric
  let result = value.toUpperCase();
  if (result !== value) notes.push('uppercased');

  result = result.replace(/\s+/g, '');
  if (result !== value.toUpperCase().trim()) notes.push('removed spaces');

  return result;
}

function normalizeNID(value, country, notes) {
  let result = value.replace(/[\s-]/g, '');
  if (result !== value.trim()) notes.push('removed separators');

  result = result.toUpperCase();
  return result;
}

function normalizeDriverLicense(value, country, notes) {
  let result = value.replace(/[\s-]/g, '');
  if (result !== value.trim()) notes.push('removed separators');

  result = result.toUpperCase();
  return result;
}

/**
 * Validate identifier format based on type.
 */
function validateIdentifierFormat(identifierType, normalizedValue, issuerCountry) {
  switch (identifierType) {
    case 'NIU':
      if (!/^[A-Z0-9]{10,20}$/.test(normalizedValue)) {
        return { valid: false, reason: 'NIU must be 10-20 alphanumeric characters' };
      }
      return { valid: true };

    case 'PASSPORT':
      if (!/^[A-Z0-9]{5,15}$/.test(normalizedValue)) {
        return { valid: false, reason: 'Passport must be 5-15 alphanumeric characters' };
      }
      return { valid: true };

    case 'NID':
      if (normalizedValue.length < 5 || normalizedValue.length > 20) {
        return { valid: false, reason: 'NID must be 5-20 characters' };
      }
      return { valid: true };

    case 'DRIVER_LICENSE':
      if (normalizedValue.length < 5 || normalizedValue.length > 20) {
        return { valid: false, reason: 'Driver license must be 5-20 characters' };
      }
      return { valid: true };

    default:
      return { valid: false, reason: 'Unknown identifier type' };
  }
}

module.exports = { normalizeIdentifier, validateIdentifierFormat };
