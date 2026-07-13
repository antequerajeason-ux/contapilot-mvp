# ContaPilot Worker

Versión compatible con el flujo que Cloudflare te está mostrando: **Create a Worker**.

## Configuración Cloudflare

- Build command: `npm install`
- Deploy command: `npx wrangler deploy`
- Root directory: `/`

## D1

1. Crea base D1 `contapilot_db`.
2. Ejecuta el SQL de `migrations/0001_schema.sql` en la consola de D1.
3. Copia el `database_id` de D1.
4. Pégalo en `wrangler.toml` reemplazando `REPLACE_WITH_YOUR_D1_DATABASE_ID`.

## Si falla por token

Crea un API Token en Cloudflare con permisos:

- Account → Workers Scripts → Edit
- Account → D1 → Edit
- Account → Account Settings → Read
- Zone → Workers Routes → Edit (opcional)

Luego en el proyecto, variables de entorno:

- `CLOUDFLARE_API_TOKEN` = token creado
- `CLOUDFLARE_ACCOUNT_ID` = tu Account ID


## Conectar microservicio DIAN Sync

Después de desplegar `contapilot_dian_sync_service` en Render/Railway/VPS, agrega una variable de entorno al Worker:

- Nombre: `DIAN_SYNC_SERVICE_URL`
- Valor: `https://TU-SERVICIO-DIAN.onrender.com`

En Cloudflare:

`Workers & Pages → contapilot → Settings → Variables → Add variable`

Luego redeploy.

El botón **Importar información** en el modal DIAN llamará a:

`POST {DIAN_SYNC_SERVICE_URL}/sync`

y enviará:

- URL token DIAN
- NIT empresa
- fecha inicial
- URL callback `/api/companies/{id}/upload`
- token del usuario para subir los ZIP/XML procesados
