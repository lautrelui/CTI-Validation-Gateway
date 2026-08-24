/**
 * Boot banner for CVG.
 *
 * Deliberately free of credential material. This output used to end with
 *
 *   [CVG] Login credentials: <username> / <password>
 *
 * which wrote the admin password to stdout on every start — and from there
 * into `docker logs`, the host journal, and any log shipper attached to the
 * container. The admin account is still reported, but only as a fact
 * ("configured"), never as a value. Authorized callers are listed by caller
 * id, which is an identity rather than a credential; their API keys are not
 * printed.
 *
 * Kept in its own module with no dependencies beyond the config object it is
 * handed, so src/tests/startup-banner.test.js can pin the invariant without
 * loading express or opening a listener. Anything added here must stay
 * non-sensitive — see that test for the values it refuses to find.
 *
 * @param {object} cfg  the resolved config (src/config/index.js)
 * @returns {string[]}  lines to print, in order
 */
function startupBanner(cfg) {
  const ivsUrl = cfg.ivs.mode === 'external' ? cfg.ivs.baseUrl : 'N/A (simulator)';
  return [
    `
╔═══════════════════════════════════════════════════════╗
║   CTI Verification Gateway (CVG) v1.0                ║
║   Gateway ID: ${cfg.gateway.id.padEnd(39)}║
║   Port: ${String(cfg.port).padEnd(46)}║
║   Environment: ${cfg.env.padEnd(38)}║
║   IVS Mode: ${cfg.ivs.mode.padEnd(41)}║
║   IVS URL: ${ivsUrl.padEnd(42)}║
║   Central DIT: ${(cfg.centralDit.baseUrl || 'N/A').padEnd(37)}║
║   Queue: ${(cfg.queue.enabled ? 'enabled' : 'disabled').padEnd(45)}║
║   Dashboard: http://localhost:${cfg.port}/dashboard${' '.repeat(14)}║
║   Health: http://localhost:${cfg.port}/api/v1/health${' '.repeat(11)}║
╚═══════════════════════════════════════════════════════╝
    `.trim(),
    '',
    '[CVG] admin authentication configured',
    `[CVG] Authorized OneBox nodes: ${Object.keys(cfg.authorizedCallers).join(', ')}`,
    '',
  ];
}

module.exports = { startupBanner };
