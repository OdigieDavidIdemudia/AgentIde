import { WebSocket } from 'ws';

// How long a superseded socket is left alone before being closed. Long enough
// for the newest registration to settle in as the socket commands are routed
// through, short enough that a genuinely replaced socket is still reaped.
const supersededSocketGraceMs = 2000;

class AgentRegistry {
  constructor() {
    this.agents = new Map();
    this.browsers = new Set();
  }

  // --- Agent Connections ---
  // addAgent registers (or re-registers) the socket for an agent. On reconnect
  // the existing entry is replaced with a fresh one, so the previously-resolved
  // dbId is carried over — otherwise a reconnecting agent becomes unaddressable
  // for event persistence (recordEvent/handleDiscovery skip agents with no
  // dbId) until it sends a new fingerprint.
  addAgent(ws, agentId) {
    const existing = this.agents.get(agentId);
    this.agents.set(agentId, { ws, agentId, dbId: existing?.dbId });
    // An agent may briefly hold two sockets (e.g. it reconnects before the old
    // one is reaped). Close the superseded socket explicitly, otherwise its
    // later 'close' event races the new registration and — because removeAgent
    // matches on socket identity — can leave the agent online and heartbeating
    // yet unreachable for commands.
    //
    // The close is deliberately deferred rather than immediate. Two processes
    // for the same host (e.g. the Windows service plus a manually launched
    // agent) share an agent_id; if each new registration instantly closes the
    // previous socket, the two agents evict each other in a livelock — hundreds
    // of connects per second, neither able to hold a socket. Delaying the
    // eviction gives the newest registration time to become the one in use
    // before any older socket is torn down.
    if (existing && existing.ws !== ws) {
      const superseded = existing.ws;
      setTimeout(() => {
        // Only reap if this socket is still the superseded one; a later
        // registration may already have replaced it again.
        if (superseded.readyState === superseded.OPEN) {
          try {
            superseded.close();
          } catch {
            // Already closing/closed; nothing to do.
          }
        }
      }, supersededSocketGraceMs);
    }
  }

  getAgent(agentId) {
    return this.agents.get(agentId);
  }

  setAgentDbId(agentId, dbId) {
    const conn = this.agents.get(agentId);
    if (conn) {
      conn.dbId = dbId;
    }
  }

  removeAgent(ws) {
    for (const [id, conn] of this.agents.entries()) {
      if (conn.ws === ws) {
        this.agents.delete(id);
        return id;
      }
    }
    return null;
  }

  // --- Browser Connections ---
  addBrowser(ws) {
    this.browsers.add(ws);
  }

  removeBrowser(ws) {
    this.browsers.delete(ws);
  }

  // --- Messaging ---
  broadcastToBrowsers(message) {
    const data = JSON.stringify(message);
    for (const browser of this.browsers) {
      if (browser.readyState === WebSocket.OPEN) {
        browser.send(data);
      }
    }
  }

  // sendToAgent delivers a command to a connected agent. It returns a result
  // instead of failing silently — an offline agent must produce a visible
  // error at the API layer rather than a "success" the caller never acts on.
  sendToAgent(agentId, message) {
    const conn = this.agents.get(agentId);
    if (!conn) {
      return { ok: false, error: 'Agent is not connected to the dashboard' };
    }
    if (conn.ws.readyState !== WebSocket.OPEN) {
      return { ok: false, error: 'Agent socket is not open (disconnecting or reconnecting)' };
    }
    try {
      conn.ws.send(JSON.stringify(message));
      return { ok: true };
    } catch (err) {
      return { ok: false, error: `Failed to send command: ${err.message}` };
    }
  }
}

export const registry = new AgentRegistry();
