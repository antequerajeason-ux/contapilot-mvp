-- Sincronizacion automatica desde Google Drive (Apps Script en la cuenta del contador)

-- Llave de conexion por usuario: solo permite subir facturas. Se guarda solo el hash.
CREATE TABLE IF NOT EXISTS drive_sync_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  last4 TEXT,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_drive_keys_user ON drive_sync_keys(user_id);

-- Cada archivo de Drive procesado (para no volver a enviarlo y para mostrar el resultado)
CREATE TABLE IF NOT EXISTS drive_files (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  file_id TEXT NOT NULL,
  file_name TEXT,
  folder_path TEXT,
  updated TEXT,
  status TEXT NOT NULL,
  imported INTEGER DEFAULT 0,
  duplicates INTEGER DEFAULT 0,
  errors INTEGER DEFAULT 0,
  message TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(user_id, file_id)
);
CREATE INDEX IF NOT EXISTS idx_drive_files_user ON drive_files(user_id, updated_at);

-- Cada ejecucion diaria del programa de Drive
CREATE TABLE IF NOT EXISTS drive_sync_runs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT NOT NULL,
  files_seen INTEGER DEFAULT 0,
  files_pending INTEGER DEFAULT 0,
  files_done INTEGER DEFAULT 0,
  imported INTEGER DEFAULT 0,
  duplicates INTEGER DEFAULT 0,
  errors INTEGER DEFAULT 0,
  continues INTEGER DEFAULT 0,
  message TEXT
);
CREATE INDEX IF NOT EXISTS idx_drive_runs_user ON drive_sync_runs(user_id, finished_at);
