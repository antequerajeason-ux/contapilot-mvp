-- Facturas que en Drive solo vienen en PDF: la sincronización las deja en espera y el contador las revisa
-- en ContaPilot (lectura del PDF + tabla de revisión) antes de importarlas.
CREATE TABLE IF NOT EXISTS drive_pdf_queue (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  file_id TEXT NOT NULL,
  file_name TEXT,
  folder_path TEXT,
  size INTEGER DEFAULT 0,
  content_b64 TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  invoice_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(user_id, file_id)
);
CREATE INDEX IF NOT EXISTS idx_drive_pdf_queue_user ON drive_pdf_queue(user_id, status, created_at);
