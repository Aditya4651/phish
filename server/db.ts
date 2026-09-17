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
