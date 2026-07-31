// Single source of truth for whether outbound S2S postback fires for a publisher
// (spec §5). Kept in its own tiny, dependency-free module — like pid-status.js —
// so BOTH server.js (enforcement + test tool + publisher-edit UI) and the unit
// tests require the SAME function. Requiring it never touches the server boot
// path (no DB, no cron, no app.listen), so there is no need for a require.main
// guard or a module.exports inside server.js.
//
// The test tool and UI must reflect this exact decision; otherwise a green
// "200 OK" in the tool would mislead when real conversions would skip outbound
// (the S1 false-positive UI/UX flagged, same class as the earlier B1 bug).
//
// Returns { enabled, reason } where reason ∈ 'ok' | 'no_url' | 'standard_mode' | 'inactive'.
function outboundGate(pub) {
  if (!pub || !pub.postback_url || !String(pub.postback_url).trim()) return { enabled: false, reason: 'no_url' };
  const modeOk = pub.integration_mode === 's2s_network' || pub.integration_mode === 'portal_s2s';
  if (!modeOk) return { enabled: false, reason: 'standard_mode' };
  if (pub.s2s_postback_active !== 1) return { enabled: false, reason: 'inactive' };
  return { enabled: true, reason: 'ok' };
}

module.exports = { outboundGate };
