import 'dotenv/config';
import { pool } from '../server/db.js';

const rows = await pool.query(`
  SELECT hostname, agent_version, state, assessment_id, last_seen, status
  FROM agents ORDER BY hostname
`);
for (const r of rows.rows) {
  console.log(
    `${r.hostname.padEnd(18)} v${(r.agent_version || '?').padEnd(8)} ` +
    `state=${(r.state || '-').padEnd(12)} assessment_id=${r.assessment_id || '-'} ` +
    `status=${r.status} last_seen=${r.last_seen}`,
  );
}

const stuck = await pool.query(`
  SELECT a.hostname, a.state, ass.status AS assessment_status, ass.started_at
  FROM agents a
  LEFT JOIN assessments ass ON ass.id = a.assessment_id
  WHERE a.state = 'assessment'
`);
console.log(`\nagents still flagged state='assessment': ${stuck.rows.length}`);
for (const r of stuck.rows) {
  console.log(`  ${r.hostname} -> assessment ${r.assessment_status} started ${r.started_at}`);
}

await pool.end();