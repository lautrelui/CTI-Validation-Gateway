const path = require('path');
const crypto = require('crypto');

// Generate secure defaults for development - in production these MUST come from env/vault
const DEFAULT_HMAC_KEY = process.env.CVG_HMAC_KEY || crypto.randomBytes(32).toString('hex');
const DEFAULT_SIGNING_KEY = process.env.CVG_SIGNING_PRIVATE_KEY || null;
const DEFAULT_JWT_SECRET = process.env.CVG_JWT_SECRET || crypto.randomBytes(48).toString('hex');
const DEFAULT_SESSION_SECRET = process.env.CVG_SESSION_SECRET || crypto.randomBytes(48).toString('hex');
const DEFAULT_ADMIN_PASSWORD = process.env.CVG_ADMIN_PASSWORD || 'admin';

const config = {
  port: parseInt(process.env.CVG_PORT || '3010', 10),
  env: process.env.NODE_ENV || 'development',

  db: {
    path: process.env.CVG_DB_PATH || path.join(__dirname, '..', '..', 'data', 'cvg.db'),
  },

  jwt: {
    secret: DEFAULT_JWT_SECRET,
    expiresIn: '1h',
  },

  session: {
    secret: DEFAULT_SESSION_SECRET,
    maxAge: 3600000, // 1 hour
  },

  admin: {
    username: process.env.CVG_ADMIN_USERNAME || 'admin',
    password: DEFAULT_ADMIN_PASSWORD,
  },

  hmac: {
    key: DEFAULT_HMAC_KEY,
    algorithm: 'sha256',
    keyVersion: 'v1',
  },

  signing: {
    algorithm: 'RS256',
    keyVersion: 'v1',
    // In production, load from HSM/vault
    privateKey: DEFAULT_SIGNING_KEY,
    publicKey: process.env.CVG_SIGNING_PUBLIC_KEY || null,
  },

  ivs: {
    baseUrl: process.env.IVS_BASE_URL || 'http://localhost:3001',
    verifyPath: process.env.IVS_VERIFY_PATH || '/api/v1/identifiers/verify',
    claimVerifyPath: process.env.IVS_CLAIM_VERIFY_PATH || '/api/v1/claims/verify',
    apiKey: process.env.IVS_API_KEY || '',
    signingKey: process.env.IVS_SIGNING_KEY || '',
    claimVerifyMode: process.env.IVS_CLAIM_VERIFY_MODE || 'auto', // 'local', 'remote', 'auto', 'none'
    timeout: parseInt(process.env.IVS_TIMEOUT || '30000', 10),
    instanceId: process.env.IVS_INSTANCE_ID || 'IVS-MTN-01',
    mode: process.env.IVS_MODE || 'simulator', // 'simulator' or 'external'
    healthCheckIntervalMs: parseInt(process.env.IVS_HEALTH_CHECK_INTERVAL || '15000', 10),
  },

  gateway: {
    id: process.env.CVG_GATEWAY_ID || 'CVG-CTI-01',
  },

  centralDit: {
    baseUrl: process.env.CENTRAL_DIT_BASE_URL || '',
    callbackPath: process.env.CENTRAL_DIT_CALLBACK_PATH || '/api/v1/verification/callbacks/ivs',
    timeout: parseInt(process.env.CENTRAL_DIT_TIMEOUT || '5000', 10),
    authMode: process.env.CENTRAL_DIT_AUTH_MODE || 'api_key',
    apiKey: process.env.CENTRAL_DIT_API_KEY || '',
  },

  queue: {
    enabled: process.env.CVG_QUEUE_ENABLED !== 'false',
    defaultTtlHours: parseInt(process.env.CVG_QUEUE_TTL_HOURS || '48', 10),
    retryScheduleMinutes: [1, 5, 15, 30, 60, 240, 720],
    workerIntervalMs: parseInt(process.env.CVG_QUEUE_WORKER_INTERVAL || '30000', 10),
  },

  // Authorized OneBox callers
  authorizedCallers: {
    'OBX-BGFI-01': { assujetti: 'BGFI', name: 'BGFI Congo', apiKey: process.env.OBX_BGFI_API_KEY || 'dev-key-bgfi-01' },
    'OBX-UBA-01': { assujetti: 'UBA', name: 'UBA Congo', apiKey: process.env.OBX_UBA_API_KEY || 'dev-key-uba-01' },
    'OBX-TEST-01': { assujetti: 'TEST', name: 'Test OneBox', apiKey: process.env.OBX_TEST_API_KEY || 'dev-key-test-01' },
  },

  supportedIdentifierTypes: ['NIU', 'PASSPORT', 'NID', 'DRIVER_LICENSE'],
  supportedPurposes: ['kyc_verification', 'identity_check', 'compliance_review'],
  supportedCountries: ['CG', 'CM', 'GA', 'TD', 'CF', 'GQ'],
};

module.exports = config;
