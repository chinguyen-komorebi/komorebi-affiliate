// Single source of truth for a PID's EFFECTIVE status. Kept in its own tiny,
// dependency-free module so BOTH server.js (admin + publisher renders) and the
// unit tests can require it — the UI is provably the same logic as enforcement
// (checkPidAllowed) without duplicating it, and requiring it never touches the
// server's boot path (no DB, no cron, no app.listen).
//
// Derives status from approval_state + run_state ONLY — never the advertiser's
// current mode. This matches checkPidAllowed exactly, so a PID left pending or
// rejected after the advertiser is switched to "Auto" is still reported as not
// running (the B1-R bug). Order mirrors the enforcement checks:
//   paused → rejected → pending → running.
// Returns one of: 'paused' | 'not_running_rejected' | 'not_running_pending' | 'running'.
function pidEffectiveStatus(approval_state, run_state) {
  if (run_state === 'paused')        return 'paused';
  if (approval_state === 'rejected') return 'not_running_rejected';
  if (approval_state === 'pending')  return 'not_running_pending';
  return 'running';
}

module.exports = { pidEffectiveStatus };
