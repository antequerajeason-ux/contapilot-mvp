CREATE TABLE IF NOT EXISTS dian_connections (
  company_id TEXT PRIMARY KEY,
  person_type TEXT DEFAULT 'juridica',
  representative_id_type TEXT DEFAULT 'CC',
  representative_id TEXT,
  company_nit TEXT,
  token_url TEXT,
  token_last4 TEXT,
  start_date TEXT,
  status TEXT DEFAULT 'saved',
  last_test_at TEXT,
  last_sync_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dian_sync_logs (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL,
  status TEXT NOT NULL,
  message TEXT,
  imported_count INTEGER DEFAULT 0,
  error_count INTEGER DEFAULT 0,
  created_at TEXT NOT NULL
);
