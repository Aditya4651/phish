import { relations } from 'drizzle-orm';
import { pgTable, serial, text, doublePrecision, timestamp, integer } from 'drizzle-orm/pg-core';

// Users table (Stores Clerk users, Google/GitHub accounts, and normal login users)
export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  clerkUserId: text('clerk_user_id').notNull().unique(),
  username: text('username'),
  firstName: text('first_name'),
  lastName: text('last_name'),
  email: text('email'),
  role: text('role').default('analyst'),
  passwordHash: text('password_hash'),
  apiKey: text('api_key'),
  dateOfBirth: text('date_of_birth'),
  profileImageUrl: text('profile_image_url'),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
  lastActiveAt: timestamp('last_active_at').defaultNow(),
});

// User sessions table (Persistent auth across sessions)
export const sessions = pgTable('sessions', {
  id: serial('id').primaryKey(),
  token: text('token').notNull().unique(),
  userId: integer('user_id')
    .references(() => users.id, { onDelete: 'cascade' })
    .notNull(),
  createdAt: timestamp('created_at').defaultNow(),
  expiresAt: timestamp('expires_at').notNull(),
});

// URL Scans table (Phishing scan telemetry and forensics linked to users)
export const urlScans = pgTable('url_scans', {
  id: serial('id').primaryKey(),
  userId: integer('user_id')
    .references(() => users.id, { onDelete: 'cascade' })
    .notNull(),
  url: text('url').notNull(),
  normalizedUrl: text('normalized_url').notNull(),
  scanStatus: text('scan_status').notNull(),
  riskScore: doublePrecision('risk_score').notNull(),
  result: text('result').notNull(),
  detectedThreats: text('detected_threats').notNull(),
  createdAt: timestamp('created_at').defaultNow(),
  completedAt: timestamp('completed_at').defaultNow(),
});

// Relationships
export const usersRelations = relations(users, ({ many }) => ({
  sessions: many(sessions),
  urlScans: many(urlScans),
}));

export const sessionsRelations = relations(sessions, ({ one }) => ({
  user: one(users, {
    fields: [sessions.userId],
    references: [users.id],
  }),
}));

export const urlScansRelations = relations(urlScans, ({ one }) => ({
  user: one(users, {
    fields: [urlScans.userId],
    references: [users.id],
  }),
}));
