CREATE TABLE IF NOT EXISTS invoice_batches (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
ALTER TABLE invoices ADD COLUMN batch_id TEXT;
