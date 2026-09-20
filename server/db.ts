import { createClient, Client } from '@libsql/client';
import path from 'path';
import fs from 'fs';

const DB_DIR = path.join(process.cwd(), 'PhishingURLDetector');
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

const DB_FILE = path.join(DB_DIR, 'app_database.db');

export const db: Client = createClient({
  url: `file:${DB_FILE}`,
});

export async function initDatabase(): Promise<void> {
  // Enforce foreign key constraints
  await db.execute('PRAGMA foreign_keys = ON;');

  // 1. Users Table (Clerk synchronized)
  await db.execute(`
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

  // Migrate existing users table if role column is missing
  try {
    await db.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'analyst';");
  } catch {
    // Column already exists
  }

  // Migrate api_key column if missing
  try {
    await db.execute("ALTER TABLE users ADD COLUMN api_key TEXT;");
  } catch {
    // Column already exists
  }

  // Migrate password_hash column if missing
  try {
    await db.execute("ALTER TABLE users ADD COLUMN password_hash TEXT;");
  } catch {
    // Column already exists
  }

  // 2. Sessions Table for persistent multi-user authentication
  await db.execute(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT UNIQUE NOT NULL,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  await db.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);');
  await db.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);');

  // Seed default analyst and admin accounts if they do not exist
  try {
    const now = new Date().toISOString();
    // Default Analyst Account
    await db.execute({
      sql: `
        INSERT OR IGNORE INTO users (
          id, clerk_user_id, username, first_name, last_name, email, role, created_at, updated_at, last_active_at
        ) VALUES (
          1, 'usr_analyst_default', 'analyst', 'Security', 'Analyst', 'analyst@cybersec.org', 'analyst', ?, ?, ?
        );
      `,
      args: [now, now, now],
    });

    // Default Admin Account
    await db.execute({
      sql: `
        INSERT OR IGNORE INTO users (
          id, clerk_user_id, username, first_name, last_name, email, role, created_at, updated_at, last_active_at
        ) VALUES (
          2, 'usr_admin_default', 'admin', 'Chief', 'SecOps', 'admin@phishguard.ai', 'admin', ?, ?, ?
        );
      `,
      args: [now, now, now],
    });
  } catch (seedErr) {
    console.warn('[Database] Seed accounts initialization notice:', seedErr);
  }

  // Ensure known admin username has admin role
  try {
    await db.execute({
      sql: "UPDATE users SET role = 'admin' WHERE LOWER(username) = 'admin';",
      args: [],
    });
  } catch {
    // Non-fatal
  }

  // 2. URL Scans Table (Relational with Foreign Key to users.id)
  await db.execute(`
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

  // 3. Performance & Lookup Indexes
  await db.execute('CREATE INDEX IF NOT EXISTS idx_users_clerk_id ON users(clerk_user_id);');
  await db.execute('CREATE INDEX IF NOT EXISTS idx_scans_user_id ON url_scans(user_id);');
  await db.execute('CREATE INDEX IF NOT EXISTS idx_scans_created_at ON url_scans(created_at DESC);');

  console.log('[Database] Relational SQLite database initialized successfully at', DB_FILE);
}
