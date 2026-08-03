CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS companies (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  nit TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(owner_user_id, nit)
);
CREATE TABLE IF NOT EXISTS accounting_settings (
  company_id TEXT PRIMARY KEY,
  vat_account TEXT DEFAULT '240805',
  vat_description TEXT DEFAULT 'IVA descontable',
  payable_account TEXT DEFAULT '220505',
  payable_description TEXT DEFAULT 'Proveedor por pagar',
  withholding_account TEXT DEFAULT '236540',
  withholding_description TEXT DEFAULT 'Retención en la fuente por pagar',
  default_cost_center TEXT DEFAULT 'Administración',
  default_expense_account TEXT DEFAULT '519595',
  default_expense_description TEXT DEFAULT 'Gastos diversos'
);
CREATE TABLE IF NOT EXISTS accounting_rules (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL,
  match_type TEXT NOT NULL,
  match_value TEXT NOT NULL,
  account TEXT NOT NULL,
  description TEXT NOT NULL,
  cost_center TEXT,
  priority INTEGER DEFAULT 100,
  active INTEGER DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invoices (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL,
  invoice_number TEXT NOT NULL,
  cufe TEXT NOT NULL,
  issue_date TEXT,
  document_type TEXT,
  supplier_name TEXT,
  supplier_nit TEXT,
  customer_name TEXT,
  customer_nit TEXT,
  currency TEXT DEFAULT 'COP',
  subtotal REAL DEFAULT 0,
  tax_amount REAL DEFAULT 0,
  withholding_amount REAL DEFAULT 0,
  payable_amount REAL DEFAULT 0,
  status TEXT DEFAULT 'received',
  raw_xml TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(company_id, cufe)
);
CREATE TABLE IF NOT EXISTS invoice_items (
  id TEXT PRIMARY KEY,
  invoice_id TEXT NOT NULL,
  description TEXT,
  quantity REAL DEFAULT 0,
  line_amount REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS accounting_entries (
  id TEXT PRIMARY KEY,
  invoice_id TEXT NOT NULL UNIQUE,
  status TEXT DEFAULT 'suggested',
  confidence REAL DEFAULT 0.88,
  created_at TEXT NOT NULL,
  approved_at TEXT
);
CREATE TABLE IF NOT EXISTS accounting_entry_lines (
  id TEXT PRIMARY KEY,
  entry_id TEXT NOT NULL,
  account TEXT NOT NULL,
  description TEXT NOT NULL,
  debit REAL DEFAULT 0,
  credit REAL DEFAULT 0,
  cost_center TEXT
);
