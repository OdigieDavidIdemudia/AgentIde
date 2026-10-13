import './env.js'; // must load .env before the pool is created
import pg from 'pg';
const { Pool } = pg;

// Connection config comes from the environment — never hardcode credentials.
// Set DATABASE_URL (postgres://user:pass@host:port/db) or the individual
// PGHOST / PGPORT / PGUSER / PGPASSWORD / PGDATABASE variables in ../.env
export const pool = new Pool(
  process.env.DATABASE_URL
    ? { connectionString: process.env.DATABASE_URL }
    : {
        host: process.env.PGHOST || 'localhost',
        port: Number(process.env.PGPORT) || 5432,
        user: process.env.PGUSER || 'postgres',
        password: process.env.PGPASSWORD || '',
        database: process.env.PGDATABASE || 'postgres',
      },
);

export const migrate = async () => {
  console.log('Running database migrations...');
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS agents (
        id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        hostname     TEXT NOT NULL,
        ip           TEXT,
        mac          TEXT,
        os           TEXT,
        os_version   TEXT,
        kernel_build TEXT,
        arch         TEXT,
        status       TEXT DEFAULT 'offline',
        mode         TEXT DEFAULT 'passive',
        vendor       TEXT,
        last_seen    TIMESTAMPTZ,
        registered_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(hostname, mac)
      );

      CREATE TABLE IF NOT EXISTS assessments (
        id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        agent_id    UUID REFERENCES agents(id),
        vendor      TEXT,
        profile     TEXT,
        duration_days INT,
        modules     TEXT[],
        status      TEXT DEFAULT 'running',
        score       FLOAT,
        passed      INT,
        failed      INT,
        skipped     INT,
        started_at  TIMESTAMPTZ DEFAULT NOW(),
        completed_at TIMESTAMPTZ
      );

      CREATE TABLE IF NOT EXISTS results (
        id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        assessment_id UUID REFERENCES assessments(id),
        module_name   TEXT,
        action        TEXT,
        passed        BOOLEAN,
        detail        TEXT,
        elapsed_ms    BIGINT,
        notes         TEXT,
        recorded_at   TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS events (
        id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        agent_id      UUID REFERENCES agents(id),
        assessment_id UUID REFERENCES assessments(id),
        type          TEXT,
        payload       JSONB,
        received_at   TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // Columns added after the initial schema (idempotent).
    await client.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS token TEXT`);
    await client.query(`CREATE UNIQUE INDEX IF NOT EXISTS agents_token_idx ON agents (token)`);
    await client.query(`ALTER TABLE assessments ADD COLUMN IF NOT EXISTS session_id TEXT`);
    await client.query(`ALTER TABLE assessments ADD COLUMN IF NOT EXISTS allow_reboot BOOLEAN DEFAULT FALSE`);
    // Agent-reported config, surfaced by GET /api/agents/:hostname/config.
    await client.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS dashboard_url TEXT`);
    await client.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS log_path TEXT`);
    await client.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS allow_reboot BOOLEAN DEFAULT FALSE`);
    // Agent build version, reported in the fingerprint payload. Used by the
    // fleet view to show which agents are behind the build the dashboard serves.
    await client.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS agent_version TEXT`);
    // Every security vendor discovered on the host. `vendor` stays as the
    // primary/first match for backwards compatibility; `vendors` holds the full
    // list so layered estates (Defender + a third-party sensor) are not hidden.
    await client.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS vendors TEXT[]`);
    // Files/registry paths a module created. Previously these were JSON-encoded
    // into `notes`, which made them unqueryable; historical rows are still read
    // back from `notes` for backwards compatibility.
    await client.query(`ALTER TABLE results ADD COLUMN IF NOT EXISTS artifacts JSONB`);

    // ── Two-state agent model ────────────────────────────────────────────
    // 'watch'      — agent is alive and reporting heartbeats; no test running.
    // 'assessment' — an active assessment is in flight against this endpoint.
    // Presence is deliberately separate from this: at fleet scale most agents
    // are in 'watch' and only a handful are ever in 'assessment'.
    await client.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS state TEXT DEFAULT 'watch'`);
    await client.query(`ALTER TABLE agents ADD COLUMN IF NOT EXISTS assessment_id UUID`);

    // ── Read-path indexes ────────────────────────────────────────────────
    // The Reports UI queries per-agent run history and per-run results. Without
    // these both table-scan once real data accumulates.
    // Test type: blackbox | whitebox | blackbox_deployment_test.
// Previously this only ever existed as JSON inside results.notes, which made it
// unqueryable — the same mistake artifacts used to make. It belongs on the
// assessment (the run has one kind), and is mirrored per-result so an individual
// module can be attributed even if a run is later reclassified.
await client.query(`ALTER TABLE assessments ADD COLUMN IF NOT EXISTS test_type TEXT`);
await client.query(`ALTER TABLE results ADD COLUMN IF NOT EXISTS test_type TEXT`);
// Module family (malware, lolbin, antitamper, …) for grouping in reports.
await client.query(`ALTER TABLE results ADD COLUMN IF NOT EXISTS category TEXT`);
// Agent-reported per-module pass/fail counts. Stored rather than recomputed so a
// run's score reflects what the agent actually observed.
await client.query(`ALTER TABLE assessments ADD COLUMN IF NOT EXISTS score_source TEXT DEFAULT 'agent_reported'`);

await client.query(`
      CREATE INDEX IF NOT EXISTS assessments_agent_started_idx
      ON assessments (agent_id, started_at DESC)
    `);
await client.query(`
      CREATE INDEX IF NOT EXISTS assessments_agent_testtype_idx
      ON assessments (agent_id, test_type, started_at DESC)
    `);
await client.query(`
      CREATE INDEX IF NOT EXISTS results_category_idx
      ON results (assessment_id, category)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS results_assessment_idx
      ON results (assessment_id)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS assessments_running_idx
      ON assessments (agent_id) WHERE status = 'running'
    `);

    console.log('✅ Database migrations complete.');
  } catch (err) {
    console.error('❌ Migration failed:', err);
    throw err;
  } finally {
    client.release();
  }
};

if (process.argv[2] === 'migrate') {
  migrate().then(() => process.exit(0)).catch(() => process.exit(1));
}
