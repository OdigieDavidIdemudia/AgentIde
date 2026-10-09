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
