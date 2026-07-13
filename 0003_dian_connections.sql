CREATE TABLE IF NOT EXISTS import_logs (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL,
  file_name TEXT,
  status TEXT NOT NULL,
  imported_count INTEGER DEFAULT 0,
  error_count INTEGER DEFAULT 0,
  message TEXT,
  created_at TEXT NOT NULL
);
