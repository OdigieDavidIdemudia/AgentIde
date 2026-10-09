import React from 'react';
import styles from './ui.module.css';

export function EmptyState({ title, message, action }) {
  return (
    <div className={styles.emptyState}>
      <h3>{title}</h3>
      <p>{message}</p>
      {action && <div className={styles.emptyAction}>{action}</div>}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }) {
  return (
    <header className={styles.pageHeader}>
      <div>
        <h2>{title}</h2>
        {subtitle && <p className={styles.subtitle}>{subtitle}</p>}
      </div>
      {actions && <div className={styles.actions}>{actions}</div>}
    </header>
  );
}

export function ConfirmModal({
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  danger = false,
  onConfirm,
  onCancel,
}) {
  return (
    <div className={styles.overlay} role="presentation" onClick={onCancel}>
      <div
        className={styles.modal}
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 id="confirm-title">{title}</h3>
        <p className={styles.modalText}>{message}</p>
        <div className={styles.modalActions}>
          <button type="button" className="btn-secondary" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button
            type="button"
            className={danger ? 'btn-danger' : 'btn-primary'}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

export function Toast({ message, tone = 'info' }) {
  if (!message) return null;
  return (
    <div className={`${styles.toast} ${styles[tone] || styles.info}`} role="status">
      {message}
    </div>
  );
}
