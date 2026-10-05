import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AgentProvider } from './context/AgentContext.jsx';
import Sidebar from './components/Sidebar.jsx';
import { setToken } from './api.js';

// Pages
import FleetView from './pages/FleetView/FleetView.jsx';
import Login from './pages/Login/Login.jsx';

// Base pages with standard empty states (admin-standard.json)
const EmptyState = ({ title, message, action }) => (
  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 'var(--spacing-2xl)', border: '1px dashed var(--border)', borderRadius: '4px', textAlign: 'center', marginTop: 'var(--spacing-xl)' }}>
    <h3>{title}</h3>
    <p style={{ margin: 'var(--spacing-md) 0' }}>{message}</p>
    {action}
  </div>
);

import Assessments from './pages/Assessments/Assessments.jsx';
import LiveConsole from './pages/LiveConsole/LiveConsole.jsx';

import Reports from './pages/Reports/Reports.jsx';
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
        <Sidebar onLogout={handleLogout} />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<FleetView />} />
            <Route path="/assessment" element={<Assessments />} />
            <Route path="/assessment/:hostname" element={<Assessments />} />
            <Route path="/console" element={<LiveConsole />} />
            <Route path="/console/:assessmentId" element={<LiveConsole />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/users" element={<Users />} />
          </Routes>
        </main>
      </BrowserRouter>
    </AgentProvider>
  );
}

export default App;

