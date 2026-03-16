const crypto = require('crypto');
const config = require('../config');

// --- HMAC Module ---

/**
 * Generate a deterministic HMAC for an identifier.
 * Input format: {identifier_type}|{issuer_country}|{normalized_value}
 * This ensures cross-type uniqueness as per spec section 4.11.
 */
function generateIdentifierHmac(identifierType, issuerCountry, normalizedValue) {
  const input = `${identifierType}|${issuerCountry}|${normalizedValue}`;
  const hmac = crypto.createHmac(config.hmac.algorithm, Buffer.from(config.hmac.key, 'hex'));
  hmac.update(input);
  return hmac.digest('base64');
}

/**
 * Generate a masked value showing only the last 4 characters.
 */
function maskValue(rawValue) {
  if (!rawValue || rawValue.length <= 4) return '****';
  const visible = rawValue.slice(-4);
  const masked = '*'.repeat(rawValue.length - 4);
  return masked + visible;
}

// --- Signing Module ---
// In production, keys come from HSM/vault. For dev, we generate an RSA key pair.

let _signingKeyPair = null;

function getSigningKeyPair() {
  if (_signingKeyPair) return _signingKeyPair;

  if (config.signing.privateKey && config.signing.publicKey) {
    _signingKeyPair = {
      privateKey: config.signing.privateKey,
      publicKey: config.signing.publicKey,
    };
  } else {
    // Generate ephemeral key pair for development
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    _signingKeyPair = { privateKey, publicKey };
  }

  return _signingKeyPair;
}

/**
 * Sign a claim payload (JSON string or object).
 */
function signClaim(claimPayload) {
  const { privateKey } = getSigningKeyPair();
  const data = typeof claimPayload === 'string' ? claimPayload : JSON.stringify(claimPayload);
  const sign = crypto.createSign('SHA256');
  sign.update(data);
  sign.end();
  return sign.sign(privateKey, 'base64');
}

/**
 * Verify a claim signature.
 */
function verifyClaim(claimPayload, signature) {
  const { publicKey } = getSigningKeyPair();
  const data = typeof claimPayload === 'string' ? claimPayload : JSON.stringify(claimPayload);
  const verify = crypto.createVerify('SHA256');
  verify.update(data);
  verify.end();
  return verify.verify(publicKey, signature, 'base64');
}

/**
 * Get the public key for distribution to verifiers.
 */
function getPublicKey() {
  return getSigningKeyPair().publicKey;
}

// --- Encryption for transient queue ---

const QUEUE_ENCRYPTION_KEY = crypto.scryptSync(
  config.hmac.key,
  'cvg-queue-encryption-salt',
  32
);

function encryptPayload(plaintext) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', QUEUE_ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const authTag = cipher.getAuthTag().toString('base64');
  return JSON.stringify({ iv: iv.toString('base64'), data: encrypted, tag: authTag });
}

function decryptPayload(encryptedJson) {
  const { iv, data, tag } = JSON.parse(encryptedJson);
  const decipher = crypto.createDecipheriv('aes-256-gcm', QUEUE_ENCRYPTION_KEY, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  let decrypted = decipher.update(data, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = {
  generateIdentifierHmac,
  maskValue,
  signClaim,
  verifyClaim,
  getPublicKey,
  encryptPayload,
  decryptPayload,
};
