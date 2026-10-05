import React, { useState } from 'react';
import styles from './Login.module.css';
import { setToken } from '../../api.js';

export default function Login({ onLogin }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) {
        setError('Invalid credentials or account locked per lockout_policy.');
        return;
      }
      const data = await res.json();
      setToken(data.token);
      onLogin();
    } catch {
      setError('Unable to reach the dashboard server.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={styles.loginContainer}>
      <div className={`card ${styles.loginBox}`}>
        <div className={styles.logoMark}>A</div>
        <h2 className={styles.title}>Sign in to AgentIde</h2>
        
        <form onSubmit={handleSubmit} className={styles.form}>
          {error && <div className={styles.errorBanner}>{error}</div>}
          
          <div className={styles.inputGroup}>
            <label htmlFor="email">Email address</label>
            <input 
              id="email" 
              type="email" 
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@agentide.local"
              required 
            />
          </div>
          
          <div className={styles.inputGroup}>
            <label htmlFor="password">Password</label>
            <input 
              id="password" 
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required 
            />
          </div>
          
          <button type="submit" className={`btn-primary ${styles.submitBtn}`} disabled={busy}>
            Sign In
          </button>
        </form>
      </div>
    </div>
  );
}
