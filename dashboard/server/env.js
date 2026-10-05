import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

// Loads ../.env (project root) into process.env.
// This module MUST be imported before db.js — the connection pool is created
// at import time, so env-based DB config only works if .env is loaded first.
const envPath = path.resolve(process.cwd(), '../.env');
if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath });
}
