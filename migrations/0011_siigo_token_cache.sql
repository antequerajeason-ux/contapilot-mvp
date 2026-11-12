-- Sesión (token) de la API de Siigo guardada por credencial, para no iniciar sesión en cada consulta.
-- Siigo bloquea con 429 ("demasiadas solicitudes") si se inicia sesión muchas veces seguidas; el token dura 24 h.
CREATE TABLE IF NOT EXISTS siigo_tokens (
  cache_key TEXT PRIMARY KEY,
  access_token TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  catalog TEXT,
  updated_at TEXT NOT NULL
);
