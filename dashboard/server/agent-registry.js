import { WebSocket } from 'ws';

class AgentRegistry {
  constructor() {
    this.agents = new Map();
    this.browsers = new Set();
  }

  // --- Agent Connections ---
  addAgent(ws, agentId) {
    this.agents.set(agentId, { ws, agentId });
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

  sendToAgent(agentId, message) {
    const conn = this.agents.get(agentId);
    if (conn && conn.ws.readyState === WebSocket.OPEN) {
      conn.ws.send(JSON.stringify(message));
    }
  }
}

export const registry = new AgentRegistry();
