import React from 'react';
import styles from './AgentContextMenu.module.css';

/**
 * AgentContextMenu — a right-click menu of agent management commands, shown at
 * the pointer over an agent row in a fleet table.
 *
 * Position is clamped to the viewport so the menu never opens off-screen near
 * the bottom or right edge. It closes on Escape, on outside click, on window
 * resize/scroll, and after an item is chosen.
 *
 * `items` is a list of:
 *   { label, onSelect, disabled, danger, hint, dividerBefore }
 */
export default function AgentContextMenu({ x, y, title, items = [], status, onClose }) {
  const ref = React.useRef(null);
  const [pos, setPos] = React.useState({ left: x, top: y });

  // Clamp into the viewport once the menu has a measurable size.
  React.useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const margin = 8;
    let left = x;
    let top = y;
    if (left + rect.width + margin > window.innerWidth) {
      left = Math.max(margin, window.innerWidth - rect.width - margin);
    }
    if (top + rect.height + margin > window.innerHeight) {
      top = Math.max(margin, y - rect.height);
    }
    setPos({ left, top });
  }, [x, y, items.length]);

  // Close on Escape / outside click / viewport changes.
  React.useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    const onDown = (e) => {
      if (ref.current && !ref.current.contains(e.target)) onClose();
    };
    const onViewportChange = () => onClose();

    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onDown);
    window.addEventListener('resize', onViewportChange);
    window.addEventListener('scroll', onViewportChange, true);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onDown);
      window.removeEventListener('resize', onViewportChange);
      window.removeEventListener('scroll', onViewportChange, true);
    };
  }, [onClose]);

  // Focus the first enabled item so the menu is keyboard-navigable.
  React.useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const first = el.querySelector('button:not(:disabled)');
    if (first) first.focus();
  }, []);

  return (
    <div
      ref={ref}
      className={styles.menu}
      style={{ left: pos.left, top: pos.top }}
      role="menu"
      aria-label={`Agent actions${title ? ` for ${title}` : ''}`}
      onContextMenu={(e) => e.preventDefault()}
    >
      {title && <div className={styles.header}>{title}</div>}

      {items.map((item, i) => {
        if (item.dividerBefore) {
          return <div key={`div-${i}`} className={styles.divider} role="separator" />;
        }
        return (
          <button
            key={item.label}
            type="button"
            role="menuitem"
            className={item.danger ? `${styles.item} ${styles.danger}` : styles.item}
            disabled={item.disabled}
            title={item.hint || item.label}
            onClick={() => {
              onClose();
              item.onSelect();
            }}
          >
            <span>{item.label}</span>
            {item.hint && <span className={styles.hint}>{item.hint}</span>}
          </button>
        );
      })}

      {status && <div className={styles.status}>{status}</div>}
    </div>
  );
}