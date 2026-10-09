import React from 'react';
import { NavLink } from 'react-router-dom';
import { useTheme } from '../hooks/useTheme.js';
import styles from './Sidebar.module.css';

export default function Sidebar({ onLogout }) {
  const { theme, toggleTheme } = useTheme();

  return (
    <aside className={styles.sidebar}>
      <div className={styles.logoContainer}>
        <div className={styles.logoMark}>A</div>
        <h1 className={styles.logoText}>AgentIde</h1>
      </div>

      <nav className={styles.nav}>
        <NavLink 
          to="/" 
          className={({ isActive }) => isActive ? `${styles.navItem} ${styles.active}` : styles.navItem}
          end
        >
          Fleet View
        </NavLink>
        <NavLink 
          to="/assessment" 
          className={({ isActive }) => isActive ? `${styles.navItem} ${styles.active}` : styles.navItem}
        >
          Assessments
        </NavLink>
        <NavLink 
          to="/console" 
          className={({ isActive }) => isActive ? `${styles.navItem} ${styles.active}` : styles.navItem}
        >
          Live Console
        </NavLink>
        <NavLink 
          to="/reports" 
          className={({ isActive }) => isActive ? `${styles.navItem} ${styles.active}` : styles.navItem}
        >
          Reports
        </NavLink>
        <div className={styles.divider} style={{ margin: 'var(--spacing-md) var(--spacing-xl)', backgroundColor: 'var(--border)', height: '1px' }}></div>
        <NavLink 
          to="/agents" 
          className={({ isActive }) => isActive ? `${styles.navItem} ${styles.active}` : styles.navItem}
        >
          Agent Management
        </NavLink>
        <NavLink 
          to="/server" 
          className={({ isActive }) => isActive ? `${styles.navItem} ${styles.active}` : styles.navItem}
        >
          Server Management
        </NavLink>
        <div className={styles.divider} style={{ margin: 'var(--spacing-md) var(--spacing-xl)', backgroundColor: 'var(--border)', height: '1px' }}></div>
        <NavLink 
          to="/users" 
          className={({ isActive }) => isActive ? `${styles.navItem} ${styles.active}` : styles.navItem}
        >
          Users & Access
        </NavLink>
      </nav>

      <div className={styles.footer}>
        <button onClick={toggleTheme} className={styles.themeToggle}>
          Switch to {theme === 'light' ? 'Dark' : 'Light'} Mode
        </button>
        <button onClick={onLogout} className={styles.themeToggle} style={{ color: 'var(--fail)' }}>
          Log Out
        </button>
        <div className={styles.version}>v0.2.0</div>
      </div>
    </aside>
  );
}
