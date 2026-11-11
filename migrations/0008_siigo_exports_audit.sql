-- Historial de exportaciones a Siigo (exitosas, fallidas y bloqueadas por duplicado)
CREATE TABLE IF NOT EXISTS siigo_exports (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL,
  invoice_id TEXT,
  invoice_number TEXT,
  cufe TEXT,
  supplier_nit TEXT,
  supplier_name TEXT,
  issue_date TEXT,
  channel TEXT DEFAULT 'api',
  status TEXT NOT NULL,
  siigo_id TEXT,
  siigo_name TEXT,
  message TEXT,
  total REAL DEFAULT 0,
  user_id TEXT,
  user_email TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_siigo_exports_company ON siigo_exports(company_id, created_at);
CREATE INDEX IF NOT EXISTS idx_siigo_exports_cufe ON siigo_exports(company_id, cufe);
CREATE INDEX IF NOT EXISTS idx_siigo_exports_number ON siigo_exports(company_id, supplier_nit, invoice_number);

-- Auditoria de cambios en la contabilizacion (generar, editar, confirmar, exportar)
CREATE TABLE IF NOT EXISTS entry_audit_log (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL,
  invoice_id TEXT NOT NULL,
  invoice_number TEXT,
  action TEXT NOT NULL,
  detail TEXT,
  user_id TEXT,
  user_email TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_entry_audit_invoice ON entry_audit_log(invoice_id, created_at);
CREATE INDEX IF NOT EXISTS idx_entry_audit_company ON entry_audit_log(company_id, created_at);

ALTER TABLE accounting_entries ADD COLUMN edited INTEGER DEFAULT 0;
ALTER TABLE accounting_entries ADD COLUMN reviewed_by TEXT;

-- Las facturas que ya estaban exportadas antes de este cambio quedan registradas,
-- para que el control de duplicados las reconozca aunque se borren y se vuelvan a cargar.
INSERT INTO siigo_exports (id, company_id, invoice_id, invoice_number, cufe, supplier_nit, supplier_name, issue_date, channel, status, message, total, created_at)
SELECT lower(hex(randomblob(16))), company_id, id, invoice_number, cufe, supplier_nit, supplier_name, issue_date, 'legacy', 'success',
       'Marcada como exportada antes de activar el historial (fecha aproximada)', payable_amount, updated_at
FROM invoices WHERE status='exported';
