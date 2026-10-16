/**
 * Confirms the enrollment-group column exists after migrate().
 *
 * The group is persisted on the agents table via an idempotent
 * ALTER TABLE ... ADD COLUMN IF NOT EXISTS, so this checks the migration
 * actually applied rather than assuming it.
 *
 * Usage: node scripts/check-agent-group-column.mjs
 */
import 'dotenv/config';
import { pool, migrate } from '../server/db.js';

await migrate();

const r = await pool.query(
  `SELECT column_name, data_type, is_nullable
     FROM information_schema.columns
    WHERE table_name = 'agents' AND column_name = 'agent_group'`,
);

if (r.rows.length === 0) {
  console.error('FAIL: agents.agent_group is missing after migrate()');
  process.exit(1);
}

const c = r.rows[0];
console.log(`OK: agents.agent_group exists (${c.data_type}, nullable=${c.is_nullable})`);

await pool.end();