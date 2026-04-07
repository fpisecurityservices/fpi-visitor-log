-- FPI Visitor Management System
-- Run this once in your Vercel Postgres console after provisioning the database

CREATE TABLE IF NOT EXISTS sites (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  pin         TEXT NOT NULL,
  token       TEXT,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS guards (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  site_id     TEXT REFERENCES sites(id) ON DELETE CASCADE,
  badge       TEXT DEFAULT '',
  added_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS settings (
  key         TEXT PRIMARY KEY,
  value       TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS logs (
  id            SERIAL PRIMARY KEY,
  date          TEXT,
  time_in       TEXT,
  full_name     TEXT,
  visitor_type  TEXT,
  company_unit  TEXT,
  id_verified   TEXT,
  site_id       TEXT,
  timestamp_iso TIMESTAMPTZ,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for fast report queries
CREATE INDEX IF NOT EXISTS idx_logs_site_id      ON logs(site_id);
CREATE INDEX IF NOT EXISTS idx_logs_date         ON logs(date);
CREATE INDEX IF NOT EXISTS idx_logs_created_at   ON logs(created_at);
CREATE INDEX IF NOT EXISTS idx_logs_visitor_type ON logs(visitor_type);
CREATE INDEX IF NOT EXISTS idx_logs_id_verified  ON logs(id_verified);

-- Default admin credentials (change password immediately after first login)
INSERT INTO settings (key, value) VALUES
  ('adminUsername', 'admin'),
  ('adminPassword', 'fpi2024'),
  ('baseUrl', '')
ON CONFLICT (key) DO NOTHING;
