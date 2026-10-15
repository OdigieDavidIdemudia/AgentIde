/**
 * Two different identifiers refer to the same endpoint, and conflating them
 * silently broke assessment launch:
 *
 *  - the `agents.id` primary key, a UUID, used for the assessments row
 *  - the hostname (e.g. DESKTOP-L07M1SS), which is what the WebSocket registry
 *    keys live sockets on
 *
 * `POST /api/assessments` used to overwrite `agent_id` with the UUID and then
 * pass that UUID to `registry.sendToAgent()`. The registry had no socket under
 * that key, so the start_assessment command was dropped without error: the
 * assessment row was created, the agent never received a command, and the run
 * produced no results. Keeping both identifiers distinct is what fixes it.
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value) {
  return typeof value === 'string' && UUID_RE.test(value);
}

/**
 * Resolve a caller-supplied agent identifier into both forms.
 *
 * `lookup(query, id)` must run `SELECT id, hostname FROM agents WHERE <key> = $1`
 * where `<key>` is `hostname` for a non-UUID input and `id` for a UUID input.
 * It resolves to `{ id, hostname }` or `undefined`.
 *
 * Returns null when the agent cannot be found, which callers must surface as a
 * 404 rather than proceeding with an undefined identifier.
 */
export async function resolveAgentIdentity(rawId, lookup) {
  const byUuid = isUuid(rawId);
  const row = await lookup(rawId, byUuid);
  if (!row) return null;
  return {
    dbId: row.id,
    socketId: row.hostname,
  };
}