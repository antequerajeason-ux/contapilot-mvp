ALTER TABLE accounting_settings ADD COLUMN vat5_account TEXT DEFAULT '24081003';
ALTER TABLE accounting_settings ADD COLUMN vat5_description TEXT DEFAULT 'Iva descontable por compras 5%';
ALTER TABLE invoices ADD COLUMN tax_breakdown TEXT;
