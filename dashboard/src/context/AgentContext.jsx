import React, { createContext, useContext, useEffect, useState, useReducer } from 'react';
import { apiFetch } from '../api.js';

const AgentContext = createContext();

const initialState = {
  agents: [],
  events: [],
  connectionStatus: 'disconnected'
};

function agentReducer(state, action) {
  switch (action.type) {
    case 'SET_AGENTS':
      return { ...state, agents: action.payload };
    case 'UPSERT_AGENT': {
      const exists = state.agents.some(a => a.hostname === action.payload.hostname);
      if (exists) {
        return { ...state, agents: state.agents.map(a => a.hostname === action.payload.hostname ? { ...a, ...action.payload } : a) };
      }
      return { ...state, agents: [...state.agents, action.payload] };
    }
    case 'UPDATE_AGENT':
      return {
        ...state,
        agents: state.agents.map(a => a.hostname === action.payload.hostname ? { ...a, ...action.payload } : a)
      };
    case 'REMOVE_AGENT':
      return {
        ...state,
        agents: state.agents.filter(a => a.hostname !== action.payload.hostname)
      };
    case 'MARK_STALE_AGENTS': {
      const now = Date.now();
      return {
        ...state,
        agents: state.agents.map(a => {
          if (a.status === 'online' && a.last_seen) {
            const lastSeenTime = new Date(a.last_seen).getTime();
            if (now - lastSeenTime > 60000) { // 60 seconds
              return { ...a, status: 'offline' };
            }
          }
          return a;
        })
      };
    }
    case 'SET_EVENTS':
      return { ...state, events: action.payload };
    case 'CLEAR_EVENTS':
      return { ...state, events: [] };
    case 'ADD_EVENT':
      return { ...state, events: [...state.events.slice(-499), action.payload] }; // keep last 500
    case 'SET_CONNECTION':
      return { ...state, connectionStatus: action.payload };
    default:
      return state;
  }
}

export function AgentProvider({ children, token }) {
  const [state, dispatch] = useReducer(agentReducer, initialState);
  const [ws, setWs] = useState(null);

  useEffect(() => {
    // Initial fetch of known agents and events (401 → re-login via apiFetch)
    apiFetch(`https://${window.location.host}/api/agents`)
      .then(res => (res.ok ? res.json() : null))
      .then(data => { if (data) dispatch({ type: 'SET_AGENTS', payload: data }); })
      .catch(err => console.error('Failed to fetch agents', err));

    apiFetch(`https://${window.location.host}/api/events`)
      .then(res => (res.ok ? res.json() : null))
      .then(data => { if (data) dispatch({ type: 'SET_EVENTS', payload: data }); })
      .catch(err => console.error('Failed to fetch events', err));

    // Establish WebSocket connection to backend (session token as query param)
    const socket = new WebSocket(
      `wss://${window.location.host}/dashboard?token=${encodeURIComponent(token || '')}`,
    );
    
    socket.onopen = () => {
      dispatch({ type: 'SET_CONNECTION', payload: 'connected' });
      setWs(socket);
    };

    socket.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      
      // Record every event in the live console stream
      dispatch({ type: 'ADD_EVENT', payload: msg });
      
      if (msg.type === 'fingerprint') {
        // New agent or re-connection — upsert into agent list. The agent
        // reports its build as `version`, but the REST rows (and the Fleet
        // view) use `agent_version`; map it here so a live WS update does not
        // wipe the value the initial /api/agents fetch supplied.
        const p = msg.payload || {};
        dispatch({ type: 'UPSERT_AGENT', payload: {
          hostname: msg.agent_id,
          status: 'online',
          last_seen: new Date().toISOString(),
          ...p,
          ...(p.version ? { agent_version: p.version } : {}),
        }});
      }

      if (msg.type === 'heartbeat') {
        dispatch({ type: 'UPDATE_AGENT', payload: { hostname: msg.agent_id, status: 'online', last_seen: new Date().toISOString() } });
      }
      
      if (msg.type === 'discovery') {
        // Agents report one entry per discovered vendor. v0.4.3+ sends an
        // array; older agents send a single object. Handle both so the Fleet
        // view populates either way.
        const entries = Array.isArray(msg.payload) ? msg.payload : [msg.payload];
        const vendors = entries
          .map(e => (e && (e.discovered_vendor || e.vendor)) || null)
          .filter(Boolean);
        if (vendors.length > 0) {
          dispatch({
            type: 'UPDATE_AGENT',
            payload: { hostname: msg.agent_id, vendor: vendors[0], vendors },
          });
        }
      }

      if (msg.type === 'agent_disconnected') {
        dispatch({ type: 'UPDATE_AGENT', payload: { hostname: msg.agent_id, status: 'offline' } });
      }
    };

    socket.onclose = () => {
      dispatch({ type: 'SET_CONNECTION', payload: 'disconnected' });
      setWs(null);
      // If the session expired the WS was rejected with 401 —
      // verify so apiFetch can force a re-login.
      apiFetch('/api/auth/me').catch(() => {});
    };

    // Stale agent cleanup: mark offline if no heartbeat for 60 seconds
    const staleInterval = setInterval(() => {
      dispatch({ type: 'MARK_STALE_AGENTS' });
    }, 15000);

    return () => {
      clearInterval(staleInterval);
      socket.close();
    };
  }, [token]);

  const sendCommand = (type, payload) => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type, ...payload }));
    }
  };

  return (
    <AgentContext.Provider value={{ state, dispatch, sendCommand }}>
      {children}
    </AgentContext.Provider>
  );
}

export const useAgentContext = () => useContext(AgentContext);
