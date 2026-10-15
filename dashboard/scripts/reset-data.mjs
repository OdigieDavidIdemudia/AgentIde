/**
 * Database reset for a clean slate.
 *
 * Deleting is destructive and irreversible, so this prints the current row
 * counts, takes a confirmation flag, and only then truncates. Pass --yes to
 * skip the prompt (for scripted resets).
 *
 * Truncation order respects the foreign keys: results/events reference
 * assessments, and assessments reference agents.
 *
 * RESTART_IDENTITY is used so agent and assessment ids restart from 1, which
 * keeps a fresh install's ids predictable.
 */
import 'dotenv/config';
import { pool } from '../server/db.js';

const confirm = process.argv.includes('--yes');

const TABLES = ['results', 'events', 'assessments', 'agents'];

async function counts() {
  const out = {};
  for (const t of TABLES) {
    const r = await pool.query(`SELECT COUNT(*)::int AS n FROM ${t}`);
    out[t] = r.rows[0].n;
  }
  return out;
}

const before = await counts();
console.log('Current row counts:');
for (const [t, n] of Object.entries(before)) {
  console.log(`  ${t.padEnd(14)} ${n}`);
}

const total = Object.values(before).reduce((a, b) => a + b, 0);

if (total === 0) {
  console.log('\nDatabase is already empty — nothing to do.');
  await pool.end();
  process.exit(0);
}

if (!confirm) {
  console.log(`\nRefusing to delete ${total} rows without confirmation.`);
  console.log('Re-run with --yes to proceed.');
  await pool.end();
  process.exit(1);
}

console.log('\nTruncating...');
await pool.query(`TRUNCATE TABLE ${TABLES.join(', ')} RESTART IDENTITY CASCADE`);

const after = await counts();
console.log('After reset:');
for (const [t, n] of Object.entries(after)) {
  console.log(`  ${t.padEnd(14)} ${n}`);
}

await pool.end();
console.log('\nDatabase reset complete. Agents must re-register on next connect.');