-- PDF original de cada factura (la representación gráfica que entrega la DIAN dentro del ZIP).
-- Se guarda en base64 (D1 admite filas de hasta 2 MB, por eso el límite es ~1,4 MB por PDF).
CREATE TABLE IF NOT EXISTS invoice_pdfs (
  invoice_id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL,
  file_name TEXT,
  size INTEGER DEFAULT 0,
  content_b64 TEXT NOT NULL,
  source TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_invoice_pdfs_company ON invoice_pdfs(company_id);
