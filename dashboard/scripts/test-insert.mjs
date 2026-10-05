import { pool } from '../server/db.js';
pool
  .query(
    "INSERT INTO assessments (agent_id, profile, duration_days, modules, status) VALUES ($1, $2, $3, $4, 'running') RETURNING *",
    ['e97dfa9d-0feb-492d-a0a5-11f24c7965b6', 'rapid', 1, ['malware']],
  )
  .then(console.log)
  .catch(console.error)
  .finally(() => process.exit(0));
