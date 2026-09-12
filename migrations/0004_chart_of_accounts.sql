CREATE TABLE IF NOT EXISTS chart_of_accounts (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL,
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT,
  clase TEXT,
  active INTEGER DEFAULT 1,
  level TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(company_id, code)
);
