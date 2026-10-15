import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AgentProvider } from './context/AgentContext.jsx';
import Sidebar from './components/Sidebar.jsx';
import { setToken } from './api.js';

// Pages
import FleetView from './pages/FleetView/FleetView.jsx';
import Login from './pages/Login/Login.jsx';
import Assessments from './pages/Assessments/Assessments.jsx';
import LiveConsole from './pages/LiveConsole/LiveConsole.jsx';
import Reports from './pages/Reports/Reports.jsx';
import AgentManagement from './pages/AgentManagement/AgentManagement.jsx';
import ServerManagement from './pages/ServerManagement/ServerManagement.jsx';
import { EmptyState } from './components/ui.jsx';

// Base pages with standard empty states (admin-standard.json)
const Users = () => <div><h2>Users & Access</h2><EmptyState title="No additional users" message="You are the only administrator. Invite team members to grant them access." action={<button className="btn-primary">Invite User</button>} /></div>;

function App() {
  const [isAuthenticated, setIsAuthenticated] = React.useState(() => {
    return !!localStorage.getItem('agentide-token');
  });

  const handleLogin = () => {
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    setToken(null);
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return <Login onLogin={handleLogin} />;
  }

  return (
    <AgentProvider token={localStorage.getItem('agentide-token')}>
      <BrowserRouter>
        {/* `scanlines` draws a faint fixed CRT overlay via ::after. It is
            pointer-events:none and sits above the UI, so it never blocks a
            click, and it is removed entirely under prefers-reduced-motion. */}
        <div className="app-shell scanlines">
          <Sidebar onLogout={handleLogout} />
          <main className="main-content">
            <Routes>
              <Route path="/" element={<FleetView />} />
              <Route path="/assessment" element={<Assessments />} />
              <Route path="/assessment/:hostname" element={<Assessments />} />
              <Route path="/console" element={<LiveConsole />} />
              <Route path="/console/:assessmentId" element={<LiveConsole />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/agents" element={<AgentManagement />} />
              <Route path="/server" element={<ServerManagement />} />
              <Route path="/users" element={<Users />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </AgentProvider>
  );
}

export default App;