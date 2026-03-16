const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const config = require('../config');

function initDatabase(dbPath) {
  const dir = path.dirname(dbPath || config.db.path);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new Database(dbPath || config.db.path);

  // Enable WAL mode for better concurrency
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  // CVG Schema
  db.exec(`
    CREATE TABLE IF NOT EXISTS verification_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      correlation_id TEXT UNIQUE NOT NULL,
      requesting_assujetti_id TEXT NOT NULL,
      onebox_id TEXT NOT NULL,
      identifier_type TEXT NOT NULL,
      masked_value_preview TEXT,
      status TEXT NOT NULL DEFAULT 'received',
      gateway_audit_ref TEXT UNIQUE NOT NULL,
      local_request_ref TEXT,
      purpose TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      completed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS verification_queue (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      correlation_id TEXT UNIQUE NOT NULL,
      encrypted_request_payload TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'queued',
      retry_count INTEGER NOT NULL DEFAULT 0,
      last_retry_at TEXT,
      next_retry_at TEXT,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (correlation_id) REFERENCES verification_requests(correlation_id)
    );

    CREATE TABLE IF NOT EXISTS verification_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      correlation_id TEXT NOT NULL,
      verification_status TEXT NOT NULL,
      claim_json TEXT,
      ivs_signature_verified INTEGER DEFAULT 0,
      received_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (correlation_id) REFERENCES verification_requests(correlation_id)
    );

    CREATE TABLE IF NOT EXISTS audit_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      correlation_id TEXT,
      entity_type TEXT,
      entity_id TEXT,
      details_json TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'viewer',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    -- IVS Schema (for embedded IVS simulator)
    CREATE TABLE IF NOT EXISTS ivs_verification_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      correlation_id TEXT UNIQUE NOT NULL,
      identifier_type TEXT NOT NULL,
      issuer_country TEXT,
      request_status TEXT NOT NULL DEFAULT 'received',
      source_context_json TEXT,
      normalization_version TEXT DEFAULT 'v1',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      completed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS ivs_verification_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id INTEGER NOT NULL,
      verification_status TEXT NOT NULL,
      identifier_hmac TEXT,
      masked_value TEXT,
      source_registry TEXT,
      confirmed_attributes_json TEXT,
      claim_id TEXT UNIQUE,
      signature_key_version TEXT DEFAULT 'v1',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (request_id) REFERENCES ivs_verification_requests(id)
    );

    CREATE TABLE IF NOT EXISTS ivs_connector_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id INTEGER NOT NULL,
      connector_name TEXT NOT NULL,
      connector_status TEXT NOT NULL,
      started_at TEXT NOT NULL,
      ended_at TEXT,
      details_json TEXT,
      FOREIGN KEY (request_id) REFERENCES ivs_verification_requests(id)
    );

    -- Indexes
    CREATE INDEX IF NOT EXISTS idx_vr_correlation ON verification_requests(correlation_id);
    CREATE INDEX IF NOT EXISTS idx_vr_status ON verification_requests(status);
    CREATE INDEX IF NOT EXISTS idx_vq_status ON verification_queue(status);
    CREATE INDEX IF NOT EXISTS idx_vq_next_retry ON verification_queue(next_retry_at);
    CREATE INDEX IF NOT EXISTS idx_ae_type ON audit_events(event_type);
    CREATE INDEX IF NOT EXISTS idx_ae_correlation ON audit_events(correlation_id);
    CREATE INDEX IF NOT EXISTS idx_ae_created ON audit_events(created_at);
  `);

  return db;
}

// Run directly to initialize
if (require.main === module) {
  const db = initDatabase();
  console.log('Database initialized at', config.db.path);
  db.close();
}

module.exports = { initDatabase };
