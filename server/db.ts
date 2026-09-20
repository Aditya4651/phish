import { Pool } from 'pg';
import { createClient, Client } from '@libsql/client';
import path from 'path';
import fs from 'fs';

// 1. PostgreSQL (Cloud SQL Developer Edition / Supabase-compatible relational DB)
let pgPoolInstance: Pool | null = null;

export function getPgPool(): Pool | null {
  if (!process.env.SQL_HOST || !process.env.SQL_USER) {
    return null;
  }
  if (!pgPoolInstance) {
    pgPoolInstance = new Pool({
      host: process.env.SQL_HOST,
      user: process.env.SQL_USER,
      password: process.env.SQL_PASSWORD,
      database: process.env.SQL_DB_NAME,
      max: 10,
      connectionTimeoutMillis: 15000,
    });

    pgPoolInstance.on('error', (err) => {
      console.error('[CloudSQL PG] Unexpected pool client error:', err);
    });
  }
  return pgPoolInstance;
}

// 2. Local fallback client
const DB_DIR = path.join(process.cwd(), 'PhishingURLDetector');
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}
const DB_FILE = path.join(DB_DIR, 'app_database.db');
const localDb: Client = createClient({
  url: `file:${DB_FILE}`,
});

export interface DatabaseExecutionResult {
  rows: any[];
  lastInsertRowid?: number | bigint;
  rowsAffected?: number;
}

/**
 * Unified query executor that directs all queries directly to Cloud SQL PostgreSQL,
 * falling back seamlessly to local database if SQL_HOST is unavailable.
 */
export async function executeQuery(query: { sql: string; args?: any[] } | string): Promise<DatabaseExecutionResult> {
  const sqlStr = typeof query === 'string' ? query : query.sql;
  const rawArgs = typeof query === 'string' ? [] : (query.args || []);
  const pool = getPgPool();

  if (pool) {
    try {
      // Convert SQLite parameter markers (?) to PostgreSQL positional markers ($1, $2...)
      let paramIndex = 1;
      let pgSql = sqlStr.replace(/\?/g, () => `$${paramIndex++}`);

      // Handle SQLite PRAGMA gracefully
      if (/^\s*PRAGMA/i.test(pgSql)) {
        return { rows: [] };
      }

      // Handle INSERT OR IGNORE
      if (/INSERT\s+OR\s+IGNORE\s+INTO/i.test(pgSql)) {
        pgSql = pgSql.replace(/INSERT\s+OR\s+IGNORE\s+INTO/i, 'INSERT INTO');
        if (!/ON\s+CONFLICT/i.test(pgSql)) {
          pgSql = pgSql.trim().replace(/;$/, '') + ' ON CONFLICT DO NOTHING;';
        }
      }

      // If INSERT query without RETURNING id, append RETURNING id
      const isInsert = /^\s*INSERT\s+INTO/i.test(pgSql);
      if (isInsert && !/RETURNING/i.test(pgSql)) {
        pgSql = pgSql.trim().replace(/;$/, '') + ' RETURNING id;';
      }

      const res = await pool.query(pgSql, rawArgs);
      const lastId = isInsert && res.rows.length > 0 && res.rows[0].id ? res.rows[0].id : undefined;

      return {
        rows: res.rows,
        lastInsertRowid: lastId,
        rowsAffected: res.rowCount ?? (res.rows ? res.rows.length : 0),
      };
    } catch (err: any) {
      console.error('[CloudSQL PG] Query error:', err.message, 'SQL:', sqlStr);
      throw err;
    }
  }

  // Fallback to SQLite
  const res = await localDb.execute(query);
  return {
    rows: res.rows,
    lastInsertRowid: res.lastInsertRowid,
    rowsAffected: res.rowsAffected,
  };
}

export const db = {
  execute: executeQuery,
};

export async function initDatabase(): Promise<void> {
  const pool = getPgPool();
  const now = new Date().toISOString();

  if (pool) {
    try {
      // Create tables on PostgreSQL
      await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          clerk_user_id TEXT UNIQUE NOT NULL,
          username TEXT,
          first_name TEXT,
          last_name TEXT,
          email TEXT,
          role TEXT DEFAULT 'analyst',
          password_hash TEXT,
          api_key TEXT,
          date_of_birth TEXT,
          profile_image_url TEXT,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          last_active_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS sessions (
          id SERIAL PRIMARY KEY,
          token TEXT UNIQUE NOT NULL,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          expires_at TIMESTAMP WITH TIME ZONE NOT NULL
        );

        CREATE TABLE IF NOT EXISTS url_scans (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          url TEXT NOT NULL,
          normalized_url TEXT NOT NULL,
          scan_status TEXT NOT NULL,
          risk_score DOUBLE PRECISION NOT NULL,
          result TEXT NOT NULL,
          detected_threats TEXT NOT NULL,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          completed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_pg_users_clerk_id ON users(clerk_user_id);
        CREATE INDEX IF NOT EXISTS idx_pg_sessions_token ON sessions(token);
        CREATE INDEX IF NOT EXISTS idx_pg_scans_user_id ON url_scans(user_id);
        CREATE INDEX IF NOT EXISTS idx_pg_scans_created_at ON url_scans(created_at DESC);
      `);

      // Seed Default Analyst & Admin accounts into Cloud SQL
      await pool.query(`
        INSERT INTO users (
          id, clerk_user_id, username, first_name, last_name, email, role, created_at, updated_at, last_active_at
        ) VALUES 
          (1, 'usr_analyst_default', 'analyst', 'Security', 'Analyst', 'analyst@cybersec.org', 'analyst', NOW(), NOW(), NOW()),
          (2, 'usr_admin_default', 'admin', 'Chief', 'SecOps', 'admin@phishguard.ai', 'admin', NOW(), NOW(), NOW())
        ON CONFLICT (clerk_user_id) DO UPDATE SET 
          username = EXCLUDED.username,
          role = EXCLUDED.role,
          last_active_at = NOW();
      `);

      // Adjust sequence so subsequent serial IDs start above 2
      await pool.query(`SELECT setval('users_id_seq', (SELECT MAX(id) FROM users));`).catch(() => {});

      console.log('[Database] Cloud SQL PostgreSQL database initialized and active in asia-southeast1.');
      return;
    } catch (pgErr) {
      console.error('[Database] Cloud SQL PostgreSQL initialization error:', pgErr);
    }
  }

  // SQLite fallback initialization
  await localDb.execute('PRAGMA foreign_keys = ON;');
  await localDb.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      clerk_user_id TEXT UNIQUE NOT NULL,
      username TEXT,
      first_name TEXT,
      last_name TEXT,
      email TEXT,
      role TEXT DEFAULT 'analyst',
      date_of_birth TEXT,
      profile_image_url TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      last_active_at TEXT NOT NULL
    );
  `);

  try {
    await localDb.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'analyst';");
  } catch {}
  try {
    await localDb.execute("ALTER TABLE users ADD COLUMN api_key TEXT;");
  } catch {}
  try {
    await localDb.execute("ALTER TABLE users ADD COLUMN password_hash TEXT;");
  } catch {}

  await localDb.execute(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT UNIQUE NOT NULL,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  await localDb.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);');
  await localDb.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);');

  await localDb.execute(`
    CREATE TABLE IF NOT EXISTS url_scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      url TEXT NOT NULL,
      normalized_url TEXT NOT NULL,
      scan_status TEXT NOT NULL,
      risk_score REAL NOT NULL,
      result TEXT NOT NULL,
      detected_threats TEXT NOT NULL,
      created_at TEXT NOT NULL,
      completed_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  await localDb.execute('CREATE INDEX IF NOT EXISTS idx_users_clerk_id ON users(clerk_user_id);');
  await localDb.execute('CREATE INDEX IF NOT EXISTS idx_scans_user_id ON url_scans(user_id);');
  await localDb.execute('CREATE INDEX IF NOT EXISTS idx_scans_created_at ON url_scans(created_at DESC);');
}
