// CORS abierto en /api: el "conector DIAN" corre como script en la consola del navegador
// desde catalogo-vpfe.dian.gov.co y necesita poder llamar a /upload directamente. La API ya
// exige el bearer token del contador en cada request, así que abrir el origen no expone nada.
const corsHeaders = { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET,POST,PUT,DELETE,OPTIONS', 'access-control-allow-headers': 'Authorization, Content-Type' };
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', ...corsHeaders }
});
const text = (data, status = 200, type = 'text/plain; charset=utf-8') => new Response(data, { status, headers: { 'content-type': type, ...corsHeaders }});
const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();
const nitClean = (v) => String(v || '').replace(/\D/g, '');
async function sha256(s){ const b=await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)); return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join(''); }
async function hashPassword(password){ const salt=id(); return salt+':'+await sha256(salt+password); }
async function verifyPassword(password, stored){ const [salt,digest]=String(stored||'').split(':'); return !!salt && await sha256(salt+password) === digest; }
function tagText(xml, tag){ const re=new RegExp(`<(?:\\w+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:\\w+:)?${tag}>`,'i'); const m=String(xml||'').match(re); return m ? strip(m[1]) : ''; }
function strip(s){ return String(s||'').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g,'$1').replace(/<[^>]*>/g,'').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&').trim(); }
function num(v){ const n=Number(String(v||'0').replace(/[^0-9.-]/g,'')); return Number.isFinite(n)?n:0; }
function innerUbl(src){ for(const tag of ['Invoice','CreditNote','DebitNote']){ const re=new RegExp(`<(?:\\w+:)?${tag}\\b[\\s\\S]*?<\\/(?:\\w+:)?${tag}>`,'i'); const m=String(src||'').match(re); if(m) return m[0]; } return null; }
function extractInvoiceXml(input){ let raw=String(input||'').trim(); if(!raw) throw new Error('Archivo vacío'); if(/^(<\?xml[\s\S]*?\?>\s*)?<(?:\w+:)?(Invoice|CreditNote|DebitNote)\b/i.test(raw)) return raw; raw=raw.replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&'); const inner=innerUbl(raw); if(inner) return inner; throw new Error('No encontré Invoice/CreditNote/DebitNote dentro del archivo'); }
function removeLineBlocks(xml){ return String(xml||'').replace(/<(?:\w+:)?InvoiceLine\b[\s\S]*?<\/(?:\w+:)?InvoiceLine>/gi,'').replace(/<(?:\w+:)?CreditNoteLine\b[\s\S]*?<\/(?:\w+:)?CreditNoteLine>/gi,'').replace(/<(?:\w+:)?DebitNoteLine\b[\s\S]*?<\/(?:\w+:)?DebitNoteLine>/gi,''); }
function sumBlocks(xml, blockTag, amountTag='TaxAmount'){
  let total=0;
  const re=new RegExp(`<(?:\\w+:)?${blockTag}\\b[\\s\\S]*?<\\/(?:\\w+:)?${blockTag}>`,'gi');
  for(const m of String(xml||'').matchAll(re)) total += num(tagText(m[0], amountTag));
  return total;
}
function round2(n){ return Math.round((Number(n)||0)*100)/100; }
// Agrupa el IVA de TaxSubtotal por porcentaje (19%, 5%, etc.) en vez de sumarlo todo junto,
// para poder llevar cada tarifa a su cuenta contable correspondiente.
function sumTaxByPercent(xml){
  const out={};
  const totalRe=new RegExp(`<(?:\\w+:)?TaxTotal\\b[\\s\\S]*?<\\/(?:\\w+:)?TaxTotal>`,'gi');
  for(const totalMatch of String(xml||'').matchAll(totalRe)){
    const subRe=new RegExp(`<(?:\\w+:)?TaxSubtotal\\b[\\s\\S]*?<\\/(?:\\w+:)?TaxSubtotal>`,'gi');
    for(const sub of totalMatch[0].matchAll(subRe)){
      const amount=num(tagText(sub[0],'TaxAmount'));
      if(!amount) continue;
      const pctRaw=tagText(sub[0],'Percent');
      const pct=String(Math.round(num(pctRaw)));
      out[pct]=round2((out[pct]||0)+amount);
    }
  }
  return out;
}

function u16(bytes,pos){ return bytes[pos] | (bytes[pos+1] << 8); }
function u32(bytes,pos){ return (bytes[pos] | (bytes[pos+1] << 8) | (bytes[pos+2] << 16) | (bytes[pos+3] << 24)) >>> 0; }
async function inflateRaw(bytes){
  if(typeof DecompressionStream === 'undefined') throw new Error('Este entorno no soporta descompresión ZIP automática. Sube el XML descomprimido.');
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
async function extractZipEntries(arrayBuffer, prefix='', depth=0, stats=null){
  stats = stats || {files:0, xml_like:0, nested_zip:0, pdf:0, skipped:0, unsupported:0, max_depth_reached:0};
  const bytes = new Uint8Array(arrayBuffer);
  let eocd = -1;
  for(let i=bytes.length-22; i>=0 && i>bytes.length-66000; i--){ if(u32(bytes,i)===0x06054b50){ eocd=i; break; } }
  if(eocd < 0) throw new Error('No pude leer el ZIP. Puede estar dañado, protegido o no ser un ZIP válido.');
  const total = u16(bytes,eocd+10);
  let cdOffset = u32(bytes,eocd+16);
  const decoder = new TextDecoder('utf-8');
  const entries=[];
  for(let n=0; n<total; n++){
    if(u32(bytes,cdOffset)!==0x02014b50) break;
    const method=u16(bytes,cdOffset+10), compSize=u32(bytes,cdOffset+20), nameLen=u16(bytes,cdOffset+28), extraLen=u16(bytes,cdOffset+30), commentLen=u16(bytes,cdOffset+32), localOffset=u32(bytes,cdOffset+42);
    const name=decoder.decode(bytes.slice(cdOffset+46, cdOffset+46+nameLen));
    cdOffset += 46 + nameLen + extraLen + commentLen;
    if(name.endsWith('/')) continue;
    stats.files++;
    const fullName = prefix ? `${prefix}/${name}` : name;
    const lower=name.toLowerCase();
    if(u32(bytes,localOffset)!==0x04034b50){ stats.skipped++; continue; }
    const ln=u16(bytes,localOffset+26), le=u16(bytes,localOffset+28);
    const dataStart=localOffset+30+ln+le;
    const compressed=bytes.slice(dataStart, dataStart+compSize);
    let contentBytes;
    if(method===0) contentBytes=compressed;
    else if(method===8) contentBytes=await inflateRaw(compressed);
    else { stats.unsupported++; continue; }

    if(lower.endsWith('.zip')){
      stats.nested_zip++;
      if(depth < 4){
        try{
          const buf=contentBytes.buffer.slice(contentBytes.byteOffset, contentBytes.byteOffset+contentBytes.byteLength);
          const nested=await extractZipEntries(buf, fullName, depth+1, stats);
          entries.push(...nested);
        }catch(e){
          stats.skipped++;
          entries.push({name:fullName, text:'', _error:`ZIP interno no procesable: ${e.message}`});
        }
      }else{
        stats.max_depth_reached++;
      }
      continue;
    }
    if(lower.endsWith('.pdf')){ stats.pdf++; continue; }
    if(!lower.endsWith('.xml') && !lower.endsWith('.html') && !lower.endsWith('.htm') && !lower.endsWith('.txt')){ stats.skipped++; continue; }
    stats.xml_like++;
    entries.push({name:fullName, text:decoder.decode(contentBytes)});
  }
  entries.stats=stats;
  return entries;
}
function zipStatsMessage(stats){
  stats=stats||{};
  const parts=[];
  if(stats.files!=null) parts.push(`${stats.files} archivo(s) revisados`);
  if(stats.xml_like) parts.push(`${stats.xml_like} XML/HTML/TXT encontrados`);
  if(stats.nested_zip) parts.push(`${stats.nested_zip} ZIP interno(s) revisados`);
  if(stats.pdf) parts.push(`${stats.pdf} PDF ignorado(s)`);
  if(stats.unsupported) parts.push(`${stats.unsupported} archivo(s) con compresión no soportada`);
  if(stats.max_depth_reached) parts.push(`${stats.max_depth_reached} ZIP interno(s) demasiado profundos`);
  return parts.join(', ');
}


function party(xml, partyTag){ const re=new RegExp(`<(?:\\w+:)?${partyTag}\\b[\\s\\S]*?<\/(?:\\w+:)?${partyTag}>`,'i'); const block=(xml.match(re)||[''])[0]; let name=tagText(block,'RegistrationName') || tagText(block,'Name'); let nit=tagText(block,'CompanyID') || tagText(block,'ID'); return {name,nit}; }

function firstBlock(xml, tag){ const re=new RegExp(`<(?:\\w+:)?${tag}\\b[\\s\\S]*?<\\/(?:\\w+:)?${tag}>`,'i'); return (String(xml||'').match(re)||[''])[0]; }
function attrText(block, tag, attr){ const re=new RegExp(`<(?:\\w+:)?${tag}\\b[^>]*\\s${attr}=["']([^"']+)["'][^>]*>`, 'i'); const m=String(block||'').match(re); return m?m[1]:''; }
function partyDetailsFromXml(xml, partyTag='AccountingSupplierParty'){
  const partyBlock=firstBlock(xml, partyTag);
  const addressBlock=firstBlock(partyBlock,'RegistrationAddress') || firstBlock(partyBlock,'Address') || firstBlock(partyBlock,'PhysicalLocation');
  const contactBlock=firstBlock(partyBlock,'Contact');
  const nit=tagText(partyBlock,'CompanyID') || tagText(partyBlock,'ID');
  const dv=attrText(partyBlock,'CompanyID','schemeID') || '';
  const name=tagText(partyBlock,'RegistrationName') || tagText(partyBlock,'Name');
  const tradeName=tagText(partyBlock,'Name');
  const addressLine=tagText(addressBlock,'Line') || tagText(addressBlock,'AddressLine') || tagText(addressBlock,'StreetName');
  const city=tagText(addressBlock,'CityName');
  const department=tagText(addressBlock,'CountrySubentity');
  const country=tagText(addressBlock,'IdentificationCode') || tagText(addressBlock,'Name');
  const phone=tagText(contactBlock,'Telephone') || tagText(partyBlock,'Telephone');
  const email=tagText(contactBlock,'ElectronicMail') || tagText(partyBlock,'ElectronicMail');
  const postal=tagText(addressBlock,'PostalZone');
  return {nit,dv,name,tradeName,address:addressLine,city,department,country,phone,email,postal};
}
function terceroObservacion(t){
  const parts=[];
  if(t.name) parts.push(`Tercero: ${t.name}`);
  if(t.nit) parts.push(`NIT: ${t.nit}${t.dv?'-'+t.dv:''}`);
  if(t.address) parts.push(`Dir: ${t.address}`);
  if(t.city) parts.push(`Ciudad: ${t.city}`);
  if(t.department) parts.push(`Depto: ${t.department}`);
  if(t.phone) parts.push(`Tel: ${t.phone}`);
  if(t.email) parts.push(`Email: ${t.email}`);
  return parts.join(' | ');
}
function csvCell(v){ return `"${String(v??'').replace(/"/g,'""')}"`; }
function moneyPlain(v){ const n=round2(Number(v||0)); return n ? String(n).replace('.', ',') : '0'; }
function monthFromDate(d){ const m=String(d||'').match(/^(\d{4})-(\d{2})-/); return m?m[2]:''; }

async function parseInvoice(input){
  const xml=extractInvoiceXml(input);
  const root=(xml.match(/<(?:\w+:)?(Invoice|CreditNote|DebitNote)\b/i)||[])[1] || (xml.match(/<(?:\w+:)?(Invoice|CreditNote|DebitNote)\b/i)||[])[1] || 'Invoice';
  const supplier=party(xml,'AccountingSupplierParty');
  const customer=party(xml,'AccountingCustomerParty');
  const invoiceNumber=tagText(xml,'ID');
  const cufe=tagText(xml,'UUID') || await sha256(xml);
  const issueDate=tagText(xml,'IssueDate');
  const currency=tagText(xml,'DocumentCurrencyCode') || 'COP';
  const monetary=(xml.match(/<(?:\w+:)?LegalMonetaryTotal\b[\s\S]*?<\/(?:\w+:)?LegalMonetaryTotal>/i)||[''])[0];
  // Subtotal = valor de las líneas (LineExtensionAmount) - descuentos + cargos a nivel de factura.
  // Antes se usaba primero TaxExclusiveAmount, pero ese campo es la BASE GRAVABLE: vale 0 cuando el proveedor
  // no cobra IVA (y es menor que el subtotal si hay líneas exentas), lo que dejaba el gasto en $0.
  const lineExt=num(tagText(monetary,'LineExtensionAmount'));
  const allowances=num(tagText(monetary,'AllowanceTotalAmount'));
  const charges=num(tagText(monetary,'ChargeTotalAmount'));
  const subtotal=round2(lineExt>0 ? lineExt-allowances+charges : num(tagText(monetary,'TaxExclusiveAmount')));
  const payable=round2(num(tagText(monetary,'PayableAmount') || tagText(monetary,'TaxInclusiveAmount')) || subtotal);

  // IMPORTANTE: DIAN puede traer TaxTotal a nivel factura y también dentro de cada línea.
  // Para no duplicar IVA, quitamos InvoiceLine/CreditNoteLine/DebitNoteLine antes de sumar impuestos globales.
  const headerXml=removeLineBlocks(xml);
  let tax=round2(sumBlocks(headerXml,'TaxTotal','TaxAmount'));
  const taxBreakdown=sumTaxByPercent(headerXml);
  let withholding=round2(sumBlocks(headerXml,'WithholdingTaxTotal','TaxAmount'));

  // Protección contable: si no viene retención explícita pero PayableAmount es menor que subtotal + IVA,
  // inferimos la diferencia como retención/deducción para que el asiento cuadre.
  const expectedGross=round2(subtotal + tax);
  const impliedWithholding=round2(expectedGross - payable);
  if(!withholding && impliedWithholding > 0.5) withholding = impliedWithholding;

  const lineTag=root==='CreditNote'?'CreditNoteLine':root==='DebitNote'?'DebitNoteLine':'InvoiceLine';
  const qtyTag=root==='CreditNote'?'CreditedQuantity':root==='DebitNote'?'DebitedQuantity':'InvoicedQuantity';
  const items=[];
  const lineRe=new RegExp(`<(?:\\w+:)?${lineTag}\\b[\\s\\S]*?<\\/(?:\\w+:)?${lineTag}>`,'gi');
  for(const m of xml.matchAll(lineRe)){
    items.push({description:tagText(m[0],'Description'), quantity:num(tagText(m[0],qtyTag)), line_amount:num(tagText(m[0],'LineExtensionAmount'))});
  }
  return {invoice_xml:xml, invoice_number:invoiceNumber, cufe, issue_date:issueDate, document_type:root==='Invoice'?'Factura compra':root==='CreditNote'?'Nota crédito':'Nota débito', supplier_name:supplier.name, supplier_nit:supplier.nit, customer_name:customer.name, customer_nit:customer.nit, currency, subtotal, tax_amount:tax, tax_breakdown:taxBreakdown, withholding_amount:withholding, payable_amount:payable, items};
}
async function auth(env, request){ const h=request.headers.get('authorization')||''; if(!h.toLowerCase().startsWith('bearer ')) throw new Response(JSON.stringify({detail:'Falta token Authorization: Bearer'}),{status:401,headers:corsHeaders}); const token=h.split(' ')[1]; const row=await env.DB.prepare('SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=?').bind(token).first(); if(!row) throw new Response(JSON.stringify({detail:'Sesión inválida'}),{status:401,headers:corsHeaders}); return row; }
async function ensureCompany(env,userId,companyId){ const c=await env.DB.prepare('SELECT * FROM companies WHERE id=? AND owner_user_id=?').bind(companyId,userId).first(); if(!c) throw new Response(JSON.stringify({detail:'Empresa no encontrada'}),{status:404,headers:corsHeaders}); return c; }
function siigoEnvFor(env, company){ return {...env, SIIGO_USERNAME: (company&&company.siigo_username)||env.SIIGO_USERNAME, SIIGO_ACCESS_KEY: (company&&company.siigo_access_key)||env.SIIGO_ACCESS_KEY, SIIGO_PARTNER_ID: (company&&company.siigo_partner_id)||env.SIIGO_PARTNER_ID }; }
function publicCompany(c){ if(!c) return c; const {siigo_access_key, ...rest}=c; return {...rest, siigo_configured: !!(c.siigo_username && c.siigo_access_key), siigo_key_last4: c.siigo_access_key ? String(c.siigo_access_key).slice(-4) : '' }; }
function isAdminUser(env, user){ const list=String(env.ADMIN_EMAILS||'').split(',').map(s=>s.trim().toLowerCase()).filter(Boolean); return list.includes(String(user.email||'').toLowerCase()); }
async function listBatches(env, companyId){
  let rows=(await env.DB.prepare('SELECT * FROM invoice_batches WHERE company_id=? ORDER BY created_at').bind(companyId).all()).results||[];
  if(!rows.length){
    const batchId=id();
    await env.DB.prepare('INSERT INTO invoice_batches (id,company_id,name,created_at) VALUES (?,?,?,?)').bind(batchId,companyId,'General',now()).run();
    rows=[{id:batchId,company_id:companyId,name:'General',created_at:now()}];
  }
  return rows;
}
async function resolveBatchId(env, companyId, requestedBatchId){
  if(requestedBatchId){
    const ok=await env.DB.prepare('SELECT id FROM invoice_batches WHERE id=? AND company_id=?').bind(requestedBatchId,companyId).first();
    if(ok) return ok.id;
  }
  const batches=await listBatches(env, companyId);
  return batches[batches.length-1].id;
}
async function getSettings(env, companyId){ const s=await env.DB.prepare('SELECT * FROM accounting_settings WHERE company_id=?').bind(companyId).first(); return normalizeSettings(s||{}); }
function normalizeSettings(s){
  // Normalización basada en plan de cuentas DISTRIBUCIONES TORRES GARCIA SAS / Siigo.
  // Evita usar cuentas padre y prefiere cuentas transaccionales.
  const out={...s};
  if(!out.vat_account || out.vat_account==='240805' || out.vat_account==='240810') out.vat_account='24081001';
  if(!out.vat_description || out.vat_description==='IVA descontable') out.vat_description='Iva descontable por compras 19%';
  if(!out.vat5_account) out.vat5_account='24081003';
  if(!out.vat5_description) out.vat5_description='Iva descontable por compras 5%';
  if(!out.payable_account || out.payable_account==='220505') out.payable_account='22050501';
  if(!out.payable_description || out.payable_description==='Proveedor por pagar') out.payable_description='Proveedores nacionales';
  if(!out.withholding_account || out.withholding_account==='236540') out.withholding_account='23654001';
  if(!out.withholding_description || out.withholding_description==='Retención en la fuente por pagar') out.withholding_description='Retención por compras 2,5%';
  if(!out.default_expense_account || out.default_expense_account==='519595') out.default_expense_account='52959505';
  if(!out.default_expense_description || out.default_expense_description==='Gastos diversos') out.default_expense_description='Gastos diversos POS';
  if(!out.default_cost_center) out.default_cost_center='Administración';
  return out;
}

async function ensureExtraSchema(env){
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS import_logs (
    id TEXT PRIMARY KEY,
    company_id TEXT NOT NULL,
    file_name TEXT,
    status TEXT NOT NULL,
    imported_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    message TEXT,
    created_at TEXT NOT NULL
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS dian_connections (
    company_id TEXT PRIMARY KEY,
    person_type TEXT DEFAULT 'juridica',
    representative_id_type TEXT DEFAULT 'CC',
    representative_id TEXT,
    company_nit TEXT,
    token_url TEXT,
    token_last4 TEXT,
    start_date TEXT,
    status TEXT DEFAULT 'saved',
    last_test_at TEXT,
    last_sync_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS dian_sync_logs (
    id TEXT PRIMARY KEY,
    company_id TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT,
    imported_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS chart_of_accounts (
    id TEXT PRIMARY KEY,
    company_id TEXT NOT NULL,
    code TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT,
    clase TEXT,
    active INTEGER DEFAULT 1,
    level TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(company_id, code)
  )`).run();
}

function parseAccountsCsv(text){
  const lines = String(text||'').split(/\r?\n/).filter(l=>l.trim().length);
  if(!lines.length) return [];
  function parseLine(line){
    const cells=[]; let cur=''; let inQuotes=false;
    for(let i=0;i<line.length;i++){
      const c=line[i];
      if(inQuotes){
        if(c==='"'){ if(line[i+1]==='"'){ cur+='"'; i++; } else inQuotes=false; }
        else cur+=c;
      }else{
        if(c==='"') inQuotes=true;
        else if(c===','){ cells.push(cur); cur=''; }
        else cur+=c;
      }
    }
    cells.push(cur);
    return cells;
  }
  const header=parseLine(lines[0]).map(h=>h.trim().toLowerCase());
  const idx={code:header.indexOf('codigo'), name:header.indexOf('nombre'), category:header.indexOf('categoria'), clase:header.indexOf('clase'), active:header.indexOf('activo'), level:header.indexOf('nivel')};
  if(idx.code<0 || idx.name<0) throw new Error('El CSV debe tener columnas: codigo,nombre,categoria,clase,activo,nivel');
  const out=[];
  for(let i=1;i<lines.length;i++){
    const cells=parseLine(lines[i]);
    const code=(cells[idx.code]||'').trim();
    if(!code) continue;
    out.push({
      code,
      name:(cells[idx.name]||'').trim(),
      category: idx.category>=0 ? (cells[idx.category]||'').trim() : '',
      clase: idx.clase>=0 ? (cells[idx.clase]||'').trim() : '',
      active: idx.active>=0 ? (String(cells[idx.active]||'').trim()==='1' || String(cells[idx.active]||'').trim().toLowerCase()==='sí' || String(cells[idx.active]||'').trim().toLowerCase()==='si' ? 1 : 0) : 1,
      level: idx.level>=0 ? (cells[idx.level]||'').trim() : ''
    });
  }
  return out;
}

async function validateAccountCode(env, companyId, code, label){
  const clean=String(code||'').trim();
  if(!clean) return;
  const total=await env.DB.prepare('SELECT COUNT(*) c FROM chart_of_accounts WHERE company_id=?').bind(companyId).first();
  if(!total || !total.c) return; // sin catálogo importado todavía: no se valida
  const row=await env.DB.prepare('SELECT * FROM chart_of_accounts WHERE company_id=? AND code=?').bind(companyId,clean).first();
  if(!row) throw new Error(`${label||'La cuenta'} ${clean} no existe en el plan de cuentas importado`);
  if(!row.active) throw new Error(`${label||'La cuenta'} ${clean} (${row.name}) está inactiva en Siigo Nube. Elige otra cuenta transaccional activa.`);
}

function parseDianAuthUrl(url){
  let u;
  try{ u=new URL(String(url||'')); }catch(e){ throw new Error('URL token DIAN inválida'); }
  if(!u.hostname.includes('catalogo-vpfe.dian.gov.co')) throw new Error('El token debe pertenecer a catalogo-vpfe.dian.gov.co');
  if(!u.pathname.toLowerCase().includes('/user/authtoken')) throw new Error('La URL debe ser de tipo /User/AuthToken');
  const pk=u.searchParams.get('pk'), rk=u.searchParams.get('rk'), token=u.searchParams.get('token');
  if(!pk || !rk || !token) throw new Error('La URL debe contener pk, rk y token');
  return {pk,rk,token,last4:token.slice(-4),url:u.toString()};
}
async function testDianTokenUrl(url){
  const parsed=parseDianAuthUrl(url);
  let status=0, finalUrl='', ok=false;
  try{
    const res=await fetch(parsed.url,{method:'GET',redirect:'manual',headers:{'user-agent':'Mozilla/5.0 ContaPilot'}});
    status=res.status; finalUrl=res.headers.get('location')||parsed.url;
    ok = status>=200 && status<400;
  }catch(e){
    // Si Cloudflare/DIAN bloquea la prueba HTTP, al menos dejamos validado formato.
    return {ok:false, format_ok:true, status:0, message:'Formato válido, pero no fue posible abrir DIAN desde Worker: '+e.message, parsed:{pk:parsed.pk,rk:parsed.rk,token_last4:parsed.last4}};
  }
  return {ok, format_ok:true, status, final_url:finalUrl, message:ok?'Token DIAN respondió. La sincronización real requiere endpoints internos del portal.':'DIAN respondió con estado '+status, parsed:{pk:parsed.pk,rk:parsed.rk,token_last4:parsed.last4}};
}

// Explorado con un token real contra catalogo-vpfe.dian.gov.co (portal de producción).
// El buscador de "Documentos recibidos" (POST /Document/GetDocumentsPageToken) no tiene
// captcha y se puede automatizar por completo. La DESCARGA del XML/ZIP de cada documento
// (GET /Document/DownloadZipFiles?trackId=...) sí exige resolver un captcha de Cloudflare
// Turnstile — eso no se automatiza (no evadimos protecciones anti-bot). Por eso esta función
// solo trae el LISTADO (metadatos reales); la descarga la termina el contador con un clic
// que lo lleva al portal de la DIAN ya autenticado.
function collectSetCookies(response){
  const cookies=[];
  for(const [k,v] of response.headers.entries()){ if(k.toLowerCase()==='set-cookie') cookies.push(v.split(';')[0]); }
  return cookies;
}
function dianDate(v){ const m=String(v||'').match(/\/Date\((\d+)\)\//); if(!m) return ''; return new Date(Number(m[1])).toISOString().slice(0,10); }
async function dianAuthenticatedFetch(tokenUrl){
  const parsed=parseDianAuthUrl(tokenUrl);
  const jar=[];
  let url=parsed.url, hops=0, html='';
  while(hops++ < 6){
    const res=await fetch(url,{redirect:'manual', headers:{'user-agent':'Mozilla/5.0 ContaPilot','cookie':jar.join('; ')}});
    jar.push(...collectSetCookies(res));
    const loc=res.headers.get('location');
    if(loc && res.status>=300 && res.status<400){ url=new URL(loc, url).toString(); continue; }
    html=await res.text();
    break;
  }
  const tokenMatch=html.match(/name=["']__RequestVerificationToken["'][^>]*value=["']([^"']+)["']/i);
  if(!tokenMatch) throw new Error('No pude iniciar sesión con ese token DIAN (o ya expiró). Solicita uno nuevo desde el portal.');
  return {cookie:jar.join('; '), verificationToken:tokenMatch[1]};
}
function mapDianRow(row){
  return {
    id: row.Id,
    document_type_id: row.DocumentTypeId,
    document_type: row.DocumentTypeName,
    serie_number: row.SerieAndNumber,
    supplier_nit: row.SenderCode,
    supplier_name: row.SenderName,
    customer_nit: row.ReceiverCode,
    customer_name: row.ReceiverName,
    issue_date: dianDate(row.EmissionDate),
    reception_date: dianDate(row.ReceptionDate),
    total_amount: row.TotalAmount,
    status: row.StatusName
  };
}
async function fetchDianReceivedDocuments(tokenUrl, options){
  const session=await dianAuthenticatedFetch(tokenUrl);
  const baseBody={ draw:'1', start:'0', length:'100', DocumentKey:'', SerieAndNumber:'', SenderCode:'', ReceiverCode:'',
    StartDate:'', EndDate:'', DocumentTypeId:'00', Status:'0', IsNextPage:'false', FilterType:'3', blockIndex:'0',
    RadianStatus:'0', ContinuationToken:'', __RequestVerificationToken:session.verificationToken };
  async function search(body){
    const res=await fetch('https://catalogo-vpfe.dian.gov.co/Document/GetDocumentsPageToken',{
      method:'POST',
      headers:{'content-type':'application/x-www-form-urlencoded; charset=UTF-8','cookie':session.cookie,'user-agent':'Mozilla/5.0 ContaPilot'},
      body:new URLSearchParams(body).toString()
    });
    if(!res.ok) throw new Error('DIAN respondió '+res.status+' al buscar documentos');
    const json=await res.json();
    return (json.data||[]).map(mapDianRow);
  }
  if(options.mode==='cufes'){
    const out=[];
    for(const cufe of options.cufes){ out.push(...await search({...baseBody, DocumentKey:cufe})); }
    return out;
  }
  return await search({...baseBody, StartDate:options.start_date, EndDate:options.end_date});
}
async function chooseRule(env, companyId, inv){ const rules=(await env.DB.prepare('SELECT * FROM accounting_rules WHERE company_id=? AND active=1 ORDER BY priority').bind(companyId).all()).results || []; const text=((inv.supplier_name||'')+' '+(inv.descriptions||'')).toUpperCase(); let fallback=null; for(const r of rules){ if(r.match_type==='default'){fallback=r; continue;} if(text.includes(String(r.match_value||'').toUpperCase())) return r; } return fallback; }
function normalizeAccountCode(account){
  const a=String(account||'');
  if(a==='240805'||a==='240810') return '24081001';
  if(a==='220505') return '22050501';
  if(a==='236540') return '23654001';
  if(a==='519595'||a==='51959501') return '52959505';
  if(a==='519525') return '51952501';
  if(a==='513535') return '51353501';
  return a;
}


function inferPurchaseAccount(inv, fallbackAccount){
  const text=((inv.supplier_name||'')+' '+(inv.descriptions||'')+' '+(inv.invoice_number||'')).toUpperCase();
  // Mercancías / ferretería / materiales para la venta o inventario
  if(/FERRETER|SODIMAC|PEGANTE|CERAMIC|ALFAQUICK|MAX GRIS|CEMENTO|PINTURA|TORNILL|HERRAMIENT|MATERIAL/.test(text)) return '14350101';
  // Aseo, cafetería y consumo interno
  if(/ASEO|CAFETER|LIMPIEZA|DETERGENTE|JABON|SERVILLETA/.test(text)) return '51952501';
  return normalizeAccountCode(fallbackAccount||'52959505');
}

async function generateEntry(env, invoiceId, user=null, action='generate'){
  const inv=await env.DB.prepare('SELECT * FROM invoices WHERE id=?').bind(invoiceId).first();
  if(!inv) throw new Error('Factura no encontrada');
  if(isExportedStatus(inv.status)) throw new Error('La factura ya fue exportada a Siigo; su contabilización no se recalcula');
  const previous=user ? await entryWithLines(env, invoiceId) : null;
  // Si la factura ya estaba cargada antes de la corrección, recalculamos desde el XML guardado
  // para evitar IVA duplicado u otros valores viejos en la base.
  if(inv.raw_xml){
    try{
      const reparsed=await parseInvoice(inv.raw_xml);
      inv.invoice_number=reparsed.invoice_number || inv.invoice_number;
      inv.issue_date=reparsed.issue_date || inv.issue_date;
      inv.document_type=reparsed.document_type || inv.document_type;
      inv.supplier_name=reparsed.supplier_name || inv.supplier_name;
      inv.supplier_nit=reparsed.supplier_nit || inv.supplier_nit;
      inv.customer_name=reparsed.customer_name || inv.customer_name;
      inv.customer_nit=reparsed.customer_nit || inv.customer_nit;
      inv.currency=reparsed.currency || inv.currency;
      inv.subtotal=reparsed.subtotal;
      inv.tax_amount=reparsed.tax_amount;
      inv.tax_breakdown=JSON.stringify(reparsed.tax_breakdown||{});
      inv.withholding_amount=reparsed.withholding_amount;
      inv.payable_amount=reparsed.payable_amount;
      await env.DB.prepare('UPDATE invoices SET invoice_number=?, issue_date=?, document_type=?, supplier_name=?, supplier_nit=?, customer_name=?, customer_nit=?, currency=?, subtotal=?, tax_amount=?, withholding_amount=?, payable_amount=?, updated_at=?, tax_breakdown=? WHERE id=?')
        .bind(inv.invoice_number,inv.issue_date,inv.document_type,inv.supplier_name,inv.supplier_nit,inv.customer_name,inv.customer_nit,inv.currency,inv.subtotal,inv.tax_amount,inv.withholding_amount,inv.payable_amount,now(),inv.tax_breakdown,invoiceId).run();
    }catch(_){ /* Si falla el reparseo, usa valores guardados */ }
  }
  const settings=await getSettings(env, inv.company_id);
  const items=(await env.DB.prepare('SELECT * FROM invoice_items WHERE invoice_id=?').bind(invoiceId).all()).results||[];
  inv.descriptions=items.map(i=>i.description||'').join(' ');
  const rule=await chooseRule(env, inv.company_id, inv);
  let entry=await env.DB.prepare('SELECT * FROM accounting_entries WHERE invoice_id=?').bind(invoiceId).first();
  let entryId=entry?.id || id();
  if(entry){
    await env.DB.prepare('DELETE FROM accounting_entry_lines WHERE entry_id=?').bind(entryId).run();
    await env.DB.prepare("UPDATE accounting_entries SET status='suggested', confidence=?, created_at=?, approved_at=NULL, edited=0, reviewed_by=NULL WHERE id=?").bind(.88, now(), entryId).run();
  } else {
    await env.DB.prepare('INSERT INTO accounting_entries (id,invoice_id,status,confidence,created_at,approved_at,edited) VALUES (?,?,?,?,?,?,0)').bind(entryId, invoiceId, 'suggested', .88, now(), null).run();
  }

  const linesToInsert=[];
  const push=(account,description,debit,credit,cost='')=>{
    linesToInsert.push({account:normalizeAccountCode(account),description,debit:round2(debit||0),credit:round2(credit||0),cost});
  };

  const expenseAccount=inferPurchaseAccount(inv, rule?.account || settings.default_expense_account);
  const expenseDescription=(expenseAccount==='14350101')?'Mercancías no fabricadas':(rule?.description || settings.default_expense_description);
  push(expenseAccount, expenseDescription, inv.subtotal, 0, rule?.cost_center || settings.default_cost_center);
  // IVA por tarifa: cada porcentaje va a su propia cuenta (19% y 5% tienen cuentas distintas en el
  // plan de cuentas real). Si aparece una tarifa sin cuenta dedicada, se deja en la cuenta de IVA 19%
  // por defecto y se anota el porcentaje real en la descripción para que el contador lo note.
  let taxBreakdown={};
  try{ taxBreakdown=JSON.parse(inv.tax_breakdown||'{}')||{}; }catch(_){ taxBreakdown={}; }
  if(Object.keys(taxBreakdown).length){
    for(const [pct, amount] of Object.entries(taxBreakdown)){
      if(!amount) continue;
      if(pct==='19') push(settings.vat_account, settings.vat_description, amount, 0, '');
      else if(pct==='5') push(settings.vat5_account, settings.vat5_description, amount, 0, '');
      else if(pct==='0') continue; // IVA 0% no genera IVA descontable
      else push(settings.vat_account, `${settings.vat_description} (tarifa ${pct}% sin cuenta configurada)`, amount, 0, '');
    }
  } else if(inv.tax_amount){
    push(settings.vat_account, settings.vat_description, inv.tax_amount, 0, '');
  }
  if(inv.withholding_amount) push(settings.withholding_account, settings.withholding_description, 0, inv.withholding_amount, '');
  push(settings.payable_account, `${settings.payable_description} - ${inv.supplier_name||''}`, 0, inv.payable_amount, '');

  // Protección final: antes de guardar, cuadramos débitos y créditos para que el CSV no salga descuadrado.
  const totalDebit=round2(linesToInsert.reduce((a,l)=>a+Number(l.debit||0),0));
  const totalCredit=round2(linesToInsert.reduce((a,l)=>a+Number(l.credit||0),0));
  const diff=round2(totalDebit-totalCredit);
  if(Math.abs(diff) > 0.5){
    if(diff > 0){
      // Faltan créditos: normalmente es retención/deducción no marcada en el XML.
      push(settings.withholding_account, `${settings.withholding_description} / diferencia automática`, 0, diff, '');
    }else{
      // Faltan débitos: normalmente es cargo/descuento no clasificado. Lo llevamos al gasto default para cuadrar.
      push(settings.default_expense_account, `${settings.default_expense_description} / diferencia automática`, Math.abs(diff), 0, settings.default_cost_center||'');
    }
  }

  for(const l of linesToInsert){
    await env.DB.prepare('INSERT INTO accounting_entry_lines VALUES (?,?,?,?,?,?,?)').bind(id(), entryId, l.account, l.description, l.debit, l.credit, l.cost).run();
  }

  await env.DB.prepare("UPDATE invoices SET status='accounted', updated_at=? WHERE id=?").bind(now(), invoiceId).run();
  const lines=(await env.DB.prepare('SELECT * FROM accounting_entry_lines WHERE entry_id=? ORDER BY rowid').bind(entryId).all()).results||[];
  entry=await env.DB.prepare('SELECT * FROM accounting_entries WHERE id=?').bind(entryId).first();
  if(user){
    const detail={after:simpleLines(lines)};
    if(previous?.entry){ detail.before=simpleLines(previous.lines); detail.before_edited=!!previous.entry.edited; detail.before_status=previous.entry.status; }
    await auditLog(env, user, inv, previous?.entry ? (action==='generate'?'regenerate':action) : 'generate', detail);
  }
  return {entry,lines};
}

// ---------- Revisión, validación, auditoría e historial de exportaciones ----------
function isExportedStatus(s){ return s==='exported' || s==='exporting'; }
function fmtCop(n){
  const v=round2(Number(n)||0); const neg=v<0; const [ent,dec]=Math.abs(v).toFixed(2).split('.');
  return (neg?'-':'')+'$'+ent.replace(/\B(?=(\d{3})+(?!\d))/g,'.')+','+dec;
}
function simpleLines(lines){ return (lines||[]).map(l=>({account:String(l.account||''),description:String(l.description||''),debit:round2(l.debit),credit:round2(l.credit),cost_center:String(l.cost_center||'')})); }
async function entryWithLines(env, invoiceId){
  const entry=await env.DB.prepare('SELECT * FROM accounting_entries WHERE invoice_id=?').bind(invoiceId).first();
  const lines=entry ? ((await env.DB.prepare('SELECT * FROM accounting_entry_lines WHERE entry_id=? ORDER BY rowid').bind(entry.id).all()).results||[]) : [];
  return {entry,lines};
}
async function ensureInvoice(env, user, invoiceId){
  const inv=await env.DB.prepare('SELECT i.* FROM invoices i JOIN companies c ON c.id=i.company_id WHERE i.id=? AND c.owner_user_id=?').bind(invoiceId,user.id).first();
  if(!inv) throw new Response(JSON.stringify({detail:'Factura no encontrada'}),{status:404,headers:{'content-type':'application/json; charset=utf-8',...corsHeaders}});
  return inv;
}
async function auditLog(env, user, inv, action, detail){
  await env.DB.prepare('INSERT INTO entry_audit_log (id,company_id,invoice_id,invoice_number,action,detail,user_id,user_email,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
    .bind(id(), inv.company_id, inv.id, inv.invoice_number||'', action, JSON.stringify(detail||{}), user?.id||'', user?.email||'', now()).run();
}
async function recordExport(env, user, inv, data){
  await env.DB.prepare('INSERT INTO siigo_exports (id,company_id,invoice_id,invoice_number,cufe,supplier_nit,supplier_name,issue_date,channel,status,siigo_id,siigo_name,message,total,user_id,user_email,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .bind(id(), inv.company_id, inv.id, inv.invoice_number||'', inv.cufe||'', nitClean(inv.supplier_nit), inv.supplier_name||'', inv.issue_date||'', data.channel||'api', data.status,
      data.siigo_id!=null?String(data.siigo_id):null, data.siigo_name||null, String(data.message||'').slice(0,4000), round2(data.total!=null?data.total:inv.payable_amount), user?.id||'', user?.email||'', now()).run();
}
// Busca una exportación exitosa previa de la misma factura: por CUFE, o por NIT proveedor + número
// (así se detecta aunque la factura se haya borrado y vuelto a cargar).
async function findPriorExport(env, companyId, inv){
  return await env.DB.prepare("SELECT * FROM siigo_exports WHERE company_id=? AND status='success' AND ((cufe<>'' AND cufe=?) OR (supplier_nit<>'' AND supplier_nit=? AND invoice_number=?)) ORDER BY created_at DESC LIMIT 1")
    .bind(companyId, inv.cufe||'', nitClean(inv.supplier_nit), inv.invoice_number||'').first();
}
function priorExportMessage(prior){
  // Hora de Colombia (UTC-5, sin horario de verano) para que el mensaje coincida con lo que ve el contador.
  const t=Date.parse(prior.created_at||'');
  const when=Number.isFinite(t) ? new Date(t-5*3600*1000).toISOString().replace('T',' ').slice(0,16) : String(prior.created_at||'').slice(0,16);
  const how=prior.channel==='csv' ? ' (marcada al descargar CSV)' : prior.channel==='legacy' ? ' (antes de activar el historial)' : '';
  return `Ya fue exportada a Siigo el ${when}${how}${prior.siigo_name?` como ${prior.siigo_name}`:''}${prior.user_email?` por ${prior.user_email}`:''}. No se envía de nuevo para evitar duplicados.`;
}
// ---------- PDF original de la factura ----------
const PDF_MAX_B64=1900000; // ~1,4 MB de PDF (D1 admite filas de hasta 2 MB)
function bytesToB64(bytes){ let s=''; for(let i=0;i<bytes.length;i+=0x8000) s+=String.fromCharCode.apply(null, bytes.subarray(i,i+0x8000)); return btoa(s); }
function b64ToBytes(b64){ const bin=atob(b64); const out=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out; }
// Guarda el PDF de una factura. overwrite=false conserva el que ya exista (p. ej. al reprocesar desde Drive).
async function storeInvoicePdf(env, inv, fileName, b64, source, overwrite=true){
  b64=String(b64||'').replace(/\s/g,'');
  if(!b64) return {ok:false, error:'PDF vacío'};
  if(!b64.startsWith('JVBER')) return {ok:false, error:'El archivo no es un PDF válido'};
  if(b64.length>PDF_MAX_B64) return {ok:false, error:'El PDF supera 1,4 MB y no se pudo guardar'};
  const size=Math.floor(b64.length*3/4);
  const sql=overwrite
    ? 'INSERT INTO invoice_pdfs (invoice_id,company_id,file_name,size,content_b64,source,created_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(invoice_id) DO UPDATE SET file_name=excluded.file_name,size=excluded.size,content_b64=excluded.content_b64,source=excluded.source,created_at=excluded.created_at'
    : 'INSERT OR IGNORE INTO invoice_pdfs (invoice_id,company_id,file_name,size,content_b64,source,created_at) VALUES (?,?,?,?,?,?,?)';
  await env.DB.prepare(sql).bind(inv.id, inv.company_id, String(fileName||'factura.pdf').slice(0,200), size, b64, source||'', now()).run();
  return {ok:true, size};
}

// ---------- Sincronización con Google Drive ----------
const MONTHS_ES=['enero','febrero','marzo','abril','mayo','junio','julio','agosto','septiembre','octubre','noviembre','diciembre'];
function normName(s){ return String(s||'').normalize('NFD').replace(/[̀-ͯ]/g,'').toLowerCase().replace(/\s+/g,' ').trim(); }
// Nombre del centro de facturas, siempre "Mes Año" (ej. "Octubre 2026").
// Se usa la FECHA DE EMISIÓN de la factura: así se pueden subir las facturas por año (o todas juntas)
// y cada una cae en el centro de su mes, sin importar en qué carpeta esté guardada.
// Solo si la factura no trae fecha se intenta deducir el mes de la carpeta (ej. 2026 > RECIBIDOS > 10. OCTUBRE).
function monthBatchName(path, issueDate){
  const segs=(Array.isArray(path)?path:[]).map(s=>String(s||'').trim()).filter(Boolean);
  const label=(y,m)=>{const n=MONTHS_ES[m-1];return n.charAt(0).toUpperCase()+n.slice(1)+' '+y;};
  const iss=String(issueDate||'').match(/^(\d{4})-(\d{2})/);
  if(iss && Number(iss[2])>=1 && Number(iss[2])<=12) return label(Number(iss[1]),Number(iss[2]));
  let month=0, year=0;
  for(let i=segs.length-1;i>=0 && !month;i--){
    const n=normName(segs[i]).replace('setiembre','septiembre');
    const idx=MONTHS_ES.findIndex(mn=>n.includes(mn));
    if(idx>=0){ month=idx+1; const y=n.match(/(?:^|\D)((?:19|20)\d{2})(?:\D|$)/); if(y) year=Number(y[1]); continue; }
    const ym=n.match(/\b((?:19|20)\d{2})\s*[-_./ ]\s*(0?[1-9]|1[0-2])\b/) || n.match(/\b(0?[1-9]|1[0-2])\s*[-_./ ]\s*((?:19|20)\d{2})\b/);
    if(ym){ const a=Number(ym[1]), b=Number(ym[2]); if(a>1900){year=a;month=b}else{month=a;year=b} }
  }
  if(month && !year){ for(let i=segs.length-1;i>=0;i--){ const y=normName(segs[i]).match(/(?:^|\D)((?:19|20)\d{2})(?:\D|$)/); if(y){year=Number(y[1]);break} } }
  if(month && !year && iss) year=Number(iss[1]);
  if(month && year) return label(year,month);
  if(iss) return label(Number(iss[1]),Number(iss[2]));
  return 'Drive';
}
async function batchByName(env, companyId, name){
  const rows=(await env.DB.prepare('SELECT id,name FROM invoice_batches WHERE company_id=?').bind(companyId).all()).results||[];
  const found=rows.find(r=>normName(r.name)===normName(name));
  if(found) return found.id;
  const bid=id();
  await env.DB.prepare('INSERT INTO invoice_batches (id,company_id,name,created_at) VALUES (?,?,?,?)').bind(bid,companyId,name,now()).run();
  return bid;
}
async function authDriveKey(env, request){
  const key=String(request.headers.get('x-contapilot-key')||'').trim();
  const deny=(msg)=>new Response(JSON.stringify({detail:msg}),{status:401,headers:{'content-type':'application/json; charset=utf-8',...corsHeaders}});
  if(!key) throw deny('Falta la llave de conexión de ContaPilot');
  const row=await env.DB.prepare('SELECT k.id key_id, u.* FROM drive_sync_keys k JOIN users u ON u.id=k.user_id WHERE k.key_hash=? AND k.revoked_at IS NULL').bind(await sha256(key)).first();
  if(!row) throw deny('Llave de conexión inválida o anulada. Genera una nueva en ContaPilot → Sincronización Drive.');
  await env.DB.prepare('UPDATE drive_sync_keys SET last_used_at=? WHERE id=?').bind(now(),row.key_id).run();
  return row;
}
// Importa un XML que llega desde Drive: ubica la empresa por NIT receptor, no toca facturas ya existentes,
// lo deja en el centro del mes y lo causa automáticamente (sin confirmar ni exportar).
async function importDriveXml(env, user, xmlText, fileName, path, desde, hasta, pdf){
  const r=await importDriveXmlCore(env, user, xmlText, fileName, path, desde, hasta);
  // Si el ZIP traía el PDF de la factura, se guarda junto a ella (sin reemplazar uno que ya exista).
  if(pdf && pdf.b64 && r.invoice_id && r.company_id && (r.status==='imported'||r.status==='duplicate')){
    try{ const s=await storeInvoicePdf(env,{id:r.invoice_id,company_id:r.company_id},pdf.name,pdf.b64,'drive',false); r.pdf=s.ok?'guardado':s.error; }catch(e){ r.pdf='error: '+e.message; }
  }
  delete r.company_id;
  return r;
}
async function importDriveXmlCore(env, user, xmlText, fileName, path, desde, hasta){
  const parsed=await parseInvoice(xmlText);
  const ym=String(parsed.issue_date||'').slice(0,7);
  const dm=String(desde||'').match(/^(\d{4})-(\d{1,2})$/);
  if(dm && ym && ym < `${dm[1]}-${dm[2].padStart(2,'0')}`)
    return {status:'skipped', invoice_number:parsed.invoice_number, reason:`Emitida el ${parsed.issue_date}, antes del mes de inicio de la sincronización (${desde})`};
  const hm=String(hasta||'').match(/^(\d{4})-(\d{1,2})$/);
  if(hm && ym && ym > `${hm[1]}-${hm[2].padStart(2,'0')}`)
    return {status:'skipped', invoice_number:parsed.invoice_number, reason:`Emitida el ${parsed.issue_date}, después del mes final de la sincronización (${hasta})`};
  const nit=nitClean(parsed.customer_nit);
  const company=await env.DB.prepare('SELECT * FROM companies WHERE owner_user_id=? AND nit=?').bind(user.id,nit).first();
  if(!company) return {status:'error', invoice_number:parsed.invoice_number, error:`El receptor NIT ${parsed.customer_nit||'(vacío)'} no está creado como empresa en ContaPilot`};
  const exists=await env.DB.prepare('SELECT id,status FROM invoices WHERE company_id=? AND cufe=?').bind(company.id,parsed.cufe).first();
  if(exists) return {status:'duplicate', invoice_number:parsed.invoice_number, company:company.name, invoice_id:exists.id, company_id:company.id};
  const batchName=monthBatchName(path, parsed.issue_date);
  const batchId=await batchByName(env, company.id, batchName);
  const invId=id();
  const stmts=[env.DB.prepare('INSERT INTO invoices (id,company_id,invoice_number,cufe,issue_date,document_type,supplier_name,supplier_nit,customer_name,customer_nit,currency,subtotal,tax_amount,withholding_amount,payable_amount,status,raw_xml,created_at,updated_at,tax_breakdown,batch_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .bind(invId,company.id,parsed.invoice_number,parsed.cufe,parsed.issue_date,parsed.document_type,parsed.supplier_name,parsed.supplier_nit,parsed.customer_name,parsed.customer_nit,parsed.currency,parsed.subtotal,parsed.tax_amount,parsed.withholding_amount,parsed.payable_amount,'received',parsed.invoice_xml,now(),now(),JSON.stringify(parsed.tax_breakdown||{}),batchId)];
  for(const it of parsed.items) stmts.push(env.DB.prepare('INSERT INTO invoice_items VALUES (?,?,?,?,?)').bind(id(),invId,it.description,it.quantity,it.line_amount));
  await env.DB.batch(stmts);
  let caused=true, causeError='';
  try{ await generateEntry(env, invId, {id:user.id, email:(user.email||'')+' (Drive)'}); }catch(e){ caused=false; causeError=e.message; }
  return {status:'imported', invoice_number:parsed.invoice_number, company:company.name, batch:batchName, caused, cause_error:causeError, invoice_id:invId, company_id:company.id};
}
async function handleDriveSync(request, env, p){
  const user=await authDriveKey(env, request);
  const d=await request.json().catch(()=>({}));
  if(p==='/drive-sync/check' && request.method==='POST'){
    const files=(Array.isArray(d.files)?d.files:[]).slice(0,300).filter(f=>f&&f.id);
    if(!files.length) return json({pending:[]});
    // D1 admite como máximo 100 parámetros por consulta: se consulta en grupos de 90.
    const rows=[];
    for(let i=0;i<files.length;i+=90){
      const ids=files.slice(i,i+90).map(f=>String(f.id));
      rows.push(...((await env.DB.prepare(`SELECT file_id,updated,status FROM drive_files WHERE user_id=? AND file_id IN (${ids.map(()=>'?').join(',')})`).bind(user.id,...ids).all()).results||[]));
    }
    const byId=new Map(rows.map(r=>[r.file_id,r]));
    // Pendiente: nunca visto, modificado desde la última vez, o con errores (se reintenta, p. ej. cuando ya se creó la empresa;
    // las facturas que ya entraron se reconocen por CUFE y no se duplican).
    const pending=files.filter(f=>{const r=byId.get(String(f.id));return !r || String(r.updated)!==String(f.updated||'') || r.status!=='done'}).map(f=>String(f.id));
    return json({pending});
  }
  if(p==='/drive-sync/upload' && request.method==='POST'){
    const xml=String(d.xml||'');
    if(!xml.trim()) return json({status:'error', error:'Archivo vacío'});
    if(xml.length>8*1024*1024) return json({status:'error', error:'El XML supera 8 MB'});
    try{ return json(await importDriveXml(env, user, xml, String(d.file_name||''), Array.isArray(d.path)?d.path:[], d.desde, d.hasta, d.pdf_b64?{b64:d.pdf_b64,name:d.pdf_name}:null)); }
    catch(e){ return json({status:'error', error:e.message||String(e)}); }
  }
  if(p==='/drive-sync/done' && request.method==='POST'){
    const fileId=String(d.file_id||''); if(!fileId) return json({detail:'Falta file_id'},400);
    const imported=Number(d.imported||0), dup=Number(d.duplicates||0), errs=Number(d.errors||0);
    const status=errs && !imported && !dup ? 'error' : errs ? 'partial' : 'done';
    await env.DB.prepare(`INSERT INTO drive_files (id,user_id,file_id,file_name,folder_path,updated,status,imported,duplicates,errors,message,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(user_id,file_id) DO UPDATE SET file_name=COALESCE(NULLIF(excluded.file_name,''),drive_files.file_name), folder_path=COALESCE(NULLIF(excluded.folder_path,''),drive_files.folder_path), updated=excluded.updated, status=excluded.status, imported=drive_files.imported+excluded.imported, duplicates=excluded.duplicates, errors=excluded.errors, message=excluded.message, updated_at=excluded.updated_at`)
      .bind(id(),user.id,fileId,String(d.file_name||'').slice(0,250),(Array.isArray(d.path)?d.path.join(' / '):'').slice(0,500),String(d.updated||''),status,imported,dup,errs,String(d.message||'').slice(0,2000),now(),now()).run();
    return json({ok:true,status});
  }
  if(p==='/drive-sync/run' && request.method==='POST'){
    await env.DB.prepare('INSERT INTO drive_sync_runs (id,user_id,started_at,finished_at,files_seen,files_pending,files_done,imported,duplicates,errors,continues,message) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id(),user.id,String(d.started_at||''),now(),Number(d.files_seen||0),Number(d.files_pending||0),Number(d.files_done||0),Number(d.imported||0),Number(d.duplicates||0),Number(d.errors||0),d.continues?1:0,String(d.message||'').slice(0,2000)).run();
    return json({ok:true});
  }
  return json({detail:'Ruta no encontrada'},404);
}

async function validateEntry(env, inv, lines){
  const errors=[], warnings=[];
  const debit=round2(lines.reduce((a,l)=>a+Number(l.debit||0),0));
  const credit=round2(lines.reduce((a,l)=>a+Number(l.credit||0),0));
  if(!lines.length) errors.push('La factura no tiene contabilización. Causa la factura primero.');
  lines.forEach((l,i)=>{
    const n=i+1, d=Number(l.debit||0), c=Number(l.credit||0);
    if(!String(l.account||'').trim()) errors.push(`Línea ${n}: falta la cuenta contable`);
    else if(!/^\d{4,12}$/.test(String(l.account).trim())) errors.push(`Línea ${n}: la cuenta "${l.account}" debe ser solo números (4 a 12 dígitos)`);
    if(!Number.isFinite(d) || !Number.isFinite(c) || d<0 || c<0) errors.push(`Línea ${n}: los valores deben ser números positivos`);
    else if(d>0 && c>0) errors.push(`Línea ${n}: tiene débito y crédito al mismo tiempo`);
    else if(!d && !c) errors.push(`Línea ${n}: no tiene valor débito ni crédito`);
    if(/diferencia automática/i.test(l.description||'')) warnings.push(`Línea ${n}: ContaPilot agregó un ajuste automático de ${fmtCop(d||c)} para cuadrar el asiento. Revisa si corresponde a una retención, descuento u otro concepto.`);
  });
  if(lines.length && Math.abs(debit-credit)>0.009) errors.push(`Débitos (${fmtCop(debit)}) y créditos (${fmtCop(credit)}) no cuadran. Diferencia: ${fmtCop(debit-credit)}`);
  if(lines.length && !lines.some(l=>Number(l.debit||0)>0 && !String(l.account).startsWith('2408'))) errors.push('No hay ninguna línea de gasto, costo o inventario (débito) para enviar a Siigo');
  if(!nitClean(inv.supplier_nit)) errors.push('La factura no tiene NIT del proveedor (tercero)');
  if(!String(inv.supplier_name||'').trim()) warnings.push('La factura no tiene nombre del proveedor');
  const codes=[...new Set(lines.map(l=>String(l.account||'').trim()).filter(Boolean))];
  const chart=await env.DB.prepare('SELECT COUNT(*) c FROM chart_of_accounts WHERE company_id=?').bind(inv.company_id).first();
  if(Number(chart?.c||0)>0){
    if(codes.length){
      const rows=(await env.DB.prepare(`SELECT code, name, active FROM chart_of_accounts WHERE company_id=? AND code IN (${codes.map(()=>'?').join(',')})`).bind(inv.company_id,...codes).all()).results||[];
      const byCode=new Map(rows.map(r=>[String(r.code),r]));
      for(const code of codes){
        const r=byCode.get(code);
        if(!r) errors.push(`La cuenta ${code} no existe en el plan de cuentas cargado`);
        else if(!Number(r.active)) errors.push(`La cuenta ${code} (${r.name}) está inactiva en el plan de cuentas`);
      }
    }
  } else {
    warnings.push('No hay plan de cuentas cargado: no se pudo verificar que las cuentas existan en Siigo.');
  }
  if(lines.length){
    const vat=round2(lines.filter(l=>String(l.account).startsWith('2408')).reduce((a,l)=>a+Number(l.debit||0)-Number(l.credit||0),0));
    if(Math.abs(vat-round2(inv.tax_amount||0))>1) warnings.push(`El IVA contabilizado (${fmtCop(vat)}) no coincide con el IVA de la factura electrónica (${fmtCop(inv.tax_amount)})`);
    const expense=round2(lines.filter(l=>Number(l.debit||0)>0 && !String(l.account).startsWith('2408')).reduce((a,l)=>a+Number(l.debit||0),0));
    if(Math.abs(expense-round2(inv.subtotal||0))>1) warnings.push(`El gasto/costo contabilizado (${fmtCop(expense)}) no coincide con el subtotal de la factura (${fmtCop(inv.subtotal)})`);
    const payable=round2(lines.filter(l=>String(l.account).startsWith('2205')).reduce((a,l)=>a+Number(l.credit||0)-Number(l.debit||0),0));
    if(Math.abs(payable-round2(inv.payable_amount||0))>1) warnings.push(`La cuenta por pagar al proveedor (${fmtCop(payable)}) no coincide con el total a pagar de la factura (${fmtCop(inv.payable_amount)})`);
  }
  return {ok:!errors.length, errors, warnings, totals:{debit, credit, difference:round2(debit-credit)}};
}

async function siigoAuth(env){
  const username=env.SIIGO_USERNAME;
  const accessKey=env.SIIGO_ACCESS_KEY;
  const partnerId=env.SIIGO_PARTNER_ID || 'ContaPilot';
  if(!username || !accessKey) throw new Error('Faltan variables seguras de Siigo: SIIGO_USERNAME y SIIGO_ACCESS_KEY');
  const r=await fetch('https://api.siigo.com/auth',{
    method:'POST',
    headers:{
      'content-type':'application/json',
      'Partner-Id': partnerId
    },
    body:JSON.stringify({username, access_key:accessKey})
  });
  const txt=await r.text(); let data; try{data=JSON.parse(txt)}catch(_){data={raw:txt}}
  if(!r.ok) throw new Error(data.message || data.error || data.detail || ('Siigo auth respondió '+r.status));
  if(!data.access_token) throw new Error('Siigo no devolvió access_token');
  return {access_token:data.access_token, expires_in:data.expires_in, token_type:data.token_type||'Bearer', scope:data.scope||''};
}
async function siigoRequest(env, path, options={}){
  const auth=await siigoAuth(env);
  const partnerId=env.SIIGO_PARTNER_ID || 'ContaPilot';
  const r=await fetch(`https://api.siigo.com/v1${path}`,{
    ...options,
    headers:{
      'authorization': `Bearer ${auth.access_token}`,
      'content-type':'application/json',
      'Partner-Id': partnerId,
      ...(options.headers||{})
    }
  });
  const txt=await r.text(); let data; try{data=JSON.parse(txt)}catch(_){data={raw:txt}}
  if(!r.ok){
    const cleanBody=typeof data==='object'?JSON.stringify(data):String(data||txt);
    const sentBody=options.body ? String(options.body).slice(0,2500) : '';
    throw new Error(`Siigo API respondió ${r.status} en ${path}: ${cleanBody}${sentBody?` | Payload enviado: ${sentBody}`:''}`);
  }
  return data;
}


function invoicePrefixNumber(invoiceNumber){
  // Nunca reconstruimos el consecutivo (antes se unian todos los grupos de digitos
  // encontrados, lo que corrompia numeros como "FEV2026-000990" -> "2026000990").
  // Si no calza el patron simple prefijo+digitos, se manda tal cual llego de la DIAN.
  const raw=String(invoiceNumber||'').trim();
  const m=raw.match(/^([A-Za-z\-]*)(\d+)$/);
  if(m) return {prefix:m[1]||'', number:m[2]};
  return {prefix:'', number:raw};
}
async function siigoGetPurchaseConfig(env){
  const cfg={};
  if(env.SIIGO_PURCHASE_DOCUMENT_ID) cfg.document_id=Number(env.SIIGO_PURCHASE_DOCUMENT_ID);
  if(env.SIIGO_PAYMENT_TYPE_ID) cfg.payment_type_id=Number(env.SIIGO_PAYMENT_TYPE_ID);
  if(env.SIIGO_IVA_19_TAX_ID) cfg.iva_19_tax_id=Number(env.SIIGO_IVA_19_TAX_ID);
  if(env.SIIGO_IVA_5_TAX_ID) cfg.iva_5_tax_id=Number(env.SIIGO_IVA_5_TAX_ID);
  if(!cfg.document_id){
    const docs=await siigoRequest(env,'/document-types?type=FC');
    const first=Array.isArray(docs)?docs.find(d=>d.active):null;
    if(!first) throw new Error('No encontré tipo de comprobante FC activo en Siigo. Configura SIIGO_PURCHASE_DOCUMENT_ID.');
    cfg.document_id=first.id;
  }
  if(!cfg.payment_type_id){
    const pays=await siigoRequest(env,'/payment-types?document_type=FC');
    const first=Array.isArray(pays)?pays.find(p=>p.active):null;
    if(!first) throw new Error('No encontré forma de pago FC activa en Siigo. Configura SIIGO_PAYMENT_TYPE_ID.');
    cfg.payment_type_id=first.id;
  }
  if(!cfg.iva_19_tax_id || !cfg.iva_5_tax_id){
    const taxes=await siigoRequest(env,'/taxes');
    if(!cfg.iva_19_tax_id){
      const iva19=Array.isArray(taxes)?taxes.find(t=>t.active && String(t.type).toUpperCase()==='IVA' && Number(t.percentage)===19):null;
      if(iva19) cfg.iva_19_tax_id=iva19.id;
    }
    if(!cfg.iva_5_tax_id){
      const iva5=Array.isArray(taxes)?taxes.find(t=>t.active && String(t.type).toUpperCase()==='IVA' && Number(t.percentage)===5):null;
      if(iva5) cfg.iva_5_tax_id=iva5.id;
    }
  }
  return cfg;
}
function siigoDefaultCity(env){
  return {
    country_code: env.SIIGO_DEFAULT_COUNTRY_CODE || 'CO',
    state_code: env.SIIGO_DEFAULT_STATE_CODE || '08',
    city_code: env.SIIGO_DEFAULT_CITY_CODE || '08001'
  };
}
async function siigoFindSupplierByNit(env, nit){
  const data=await siigoRequest(env, `/customers?identification=${encodeURIComponent(nit)}`);
  const results=Array.isArray(data) ? data : (data.results||[]);
  return Array.isArray(results) && results.length ? results[0] : null;
}
async function siigoEnsureSupplier(env, invoice){
  const tercero=partyDetailsFromXml(invoice.raw_xml||'', 'AccountingSupplierParty');
  const nit=nitClean(tercero.nit || invoice.supplier_nit);
  if(!nit) throw new Error('La factura no tiene NIT de proveedor para crear/usar proveedor en Siigo');
  // Buscamos primero por NIT real en Siigo; si ya existe, lo usamos tal cual.
  // Antes se adivinaba "ya existe" a partir del texto del error de creación, lo que
  // también ocultaba errores reales (ej. NIT con formato inválido) y dejaba pasar
  // un proveedor inexistente hacia /purchases, donde fallaba de forma confusa.
  const existing=await siigoFindSupplierByNit(env, nit);
  if(existing) return {identification:nit, branch_office:0, created:false, note:'Proveedor ya existía en Siigo'};
  const name=tercero.name || invoice.supplier_name || `Proveedor ${nit}`;
  const payload={
    type:'Supplier',
    person_type:'Company',
    id_type:'31',
    identification:nit,
    name:[name],
    commercial_name:tercero.tradeName || name,
    branch_office:0,
    active:true,
    vat_responsible:true,
    fiscal_responsibilities:[{code:'R-99-PN', name:'No Aplica - Otros'}],
    address:{address:tercero.address || 'Sin direccion', city: siigoDefaultCity(env)},
    phones: tercero.phone ? [{indicative:'57', number:nitClean(tercero.phone).slice(0,10)||'3000000000'}] : [],
    contacts: tercero.email ? [{first_name:name.slice(0,50), last_name:'', email:tercero.email}] : [],
    comments:'Creado/validado desde ContaPilot'
  };
  await siigoRequest(env,'/customers',{method:'POST',body:JSON.stringify(payload)});
  return {identification:nit, branch_office:0, created:true};
}
async function buildSiigoPurchasePayload(env, invoice, lines){
  const cfg=await siigoGetPurchaseConfig(env);
  const supplier=await siigoEnsureSupplier(env, invoice);
  const pn=invoicePrefixNumber(invoice.invoice_number);
  const items=(await env.DB.prepare('SELECT * FROM invoice_items WHERE invoice_id=?').bind(invoice.id).all()).results||[];
  // Se envía exactamente la contabilización que el contador revisó y confirmó en ContaPilot:
  // cada línea débito de gasto/costo/inventario (no IVA) es un ítem de la compra en Siigo.
  // Antes se recalculaba la cuenta al subir, lo que pisaba cualquier corrección manual.
  const expenseLines=(lines||[]).filter(l=>Number(l.debit)>0 && !String(l.account).startsWith('2408'));
  if(!expenseLines.length) throw new Error('La contabilización no tiene líneas de gasto/costo para enviar a Siigo');
  const siigoItems=expenseLines.map(l=>{
    let code=normalizeAccountCode(l.account);
    if(code==='51959501' || code==='519595') code='52959505';
    const description=(expenseLines.length===1 ? (items[0]?.description || l.description) : (l.description || items[0]?.description)) || `Factura ${invoice.invoice_number}`;
    return {type:'Account', code, description:String(description).slice(0,250), quantity:1, price:round2(l.debit)};
  });
  const baseTotal=round2(siigoItems.reduce((a,it)=>a+it.price,0));
  // Siigo recalcula el IVA como subtotal*porcentaje en vez de usar el valor exacto que trae la DIAN
  // (que suele venir redondeado a pesos enteros). Si el pago no coincide centavo a centavo con ese
  // cálculo, /purchases falla con "invalid_total_payments". Por eso el pago se calcula igual que Siigo,
  // no con el payable_amount original de la factura. La tarifa se toma de la factura real (19% o 5%,
  // no se asume siempre 19%) — si trae varias tarifas mezcladas, se usa la de mayor valor y se anota
  // en las observaciones para que el contador lo revise (Siigo solo permite un impuesto por ítem aquí).
  let taxBreakdown={}; try{ taxBreakdown=JSON.parse(invoice.tax_breakdown||'{}')||{}; }catch(_){}
  const taxEntries=Object.entries(taxBreakdown).filter(([,amt])=>amt);
  let paymentValue=round2(invoice.payable_amount||0);
  let mixedRatesNote='';
  if(taxEntries.length){
    taxEntries.sort((a,b)=>b[1]-a[1]);
    const [dominantPct]=taxEntries[0];
    const taxId = dominantPct==='19' ? cfg.iva_19_tax_id : dominantPct==='5' ? cfg.iva_5_tax_id : null;
    if(taxId){
      for(const it of siigoItems) it.taxes=[{id:taxId}];
      paymentValue=round2(siigoItems.reduce((a,it)=>a+round2(it.price*(1+Number(dominantPct)/100)),0));
    } else {
      paymentValue=baseTotal;
    }
    if(taxEntries.length>1) mixedRatesNote=` [Factura con varias tarifas de IVA: ${taxEntries.map(([p,a])=>`${p}%=${a}`).join(', ')} — se aplicó ${dominantPct}%, revisar manualmente]`;
  } else if(Number(invoice.tax_amount||0)>0 && cfg.iva_19_tax_id){
    for(const it of siigoItems) it.taxes=[{id:cfg.iva_19_tax_id}];
    paymentValue=round2(siigoItems.reduce((a,it)=>a+round2(it.price*1.19),0));
  } else {
    paymentValue=baseTotal;
  }
  const payload={
    document:{id:cfg.document_id},
    date:invoice.issue_date || now().slice(0,10),
    supplier:{identification:supplier.identification, branch_office:supplier.branch_office||0},
    provider_invoice:{prefix:pn.prefix||'', number:String(pn.number||invoice.invoice_number||'').slice(0,20)},
    tax_included:false,
    observations:`Creado desde ContaPilot. Factura ${invoice.invoice_number||''}. CUFE ${(invoice.cufe||'').slice(0,64)}${mixedRatesNote}`,
    items:siigoItems,
    payments:[{id:cfg.payment_type_id, value:paymentValue, due_date:invoice.issue_date || now().slice(0,10)}]
  };
  return {payload,cfg,supplier};
}

async function handleApi(request, env){ const url=new URL(request.url); const p=url.pathname.replace(/^\/api/,'') || '/'; try{
  if(request.method==='OPTIONS') return new Response(null,{status:204, headers:corsHeaders});
  if(p==='/health') return json({ok:true, service:'contapilot-cloudflare', time:now()});
  if(p==='/auth/register' && request.method==='POST'){ const d=await request.json(); const userId=id(); const token=id()+id(); await env.DB.prepare('INSERT INTO users VALUES (?,?,?,?,?)').bind(userId,d.name||'Contador Demo',String(d.email||'').toLowerCase(),await hashPassword(d.password||''),now()).run(); await env.DB.prepare('INSERT INTO sessions VALUES (?,?,?)').bind(token,userId,now()).run(); return json({token,user:{id:userId,name:d.name||'Contador Demo',email:String(d.email||'').toLowerCase()}}); }
  if(p==='/auth/login' && request.method==='POST'){ const d=await request.json(); const u=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(String(d.email||'').toLowerCase()).first(); if(!u || !(await verifyPassword(d.password||'', u.password_hash))) return json({detail:'Correo o contraseña inválidos'},401); const token=id()+id(); await env.DB.prepare('INSERT INTO sessions VALUES (?,?,?)').bind(token,u.id,now()).run(); return json({token,user:{id:u.id,name:u.name,email:u.email}}); }
  // El programa de Google Drive se autentica con su llave de conexión, no con la sesión del navegador.
  if(request.headers.get('x-contapilot-key') && p.startsWith('/drive-sync/')) return await handleDriveSync(request, env, p);
  const user=await auth(env,request);
  if(p==='/drive-sync/status' && request.method==='GET'){
    const key=await env.DB.prepare('SELECT last4, created_at, last_used_at FROM drive_sync_keys WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1').bind(user.id).first();
    const runs=(await env.DB.prepare('SELECT * FROM drive_sync_runs WHERE user_id=? ORDER BY finished_at DESC LIMIT 10').bind(user.id).all()).results||[];
    const files=(await env.DB.prepare('SELECT * FROM drive_files WHERE user_id=? ORDER BY updated_at DESC LIMIT 40').bind(user.id).all()).results||[];
    const totals=await env.DB.prepare("SELECT COUNT(*) files, SUM(imported) imported, SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) errored FROM drive_files WHERE user_id=?").bind(user.id).first();
    return json({key:key||null, runs, files, totals});
  }
  if(p==='/drive-sync/key' && request.method==='POST'){
    const raw='cpd_'+[...crypto.getRandomValues(new Uint8Array(24))].map(b=>b.toString(16).padStart(2,'0')).join('');
    await env.DB.batch([
      env.DB.prepare('UPDATE drive_sync_keys SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL').bind(now(),user.id),
      env.DB.prepare('INSERT INTO drive_sync_keys (id,user_id,key_hash,last4,created_at) VALUES (?,?,?,?,?)').bind(id(),user.id,await sha256(raw),raw.slice(-4),now())
    ]);
    return json({ok:true, key:raw, last4:raw.slice(-4), api_base:new URL(request.url).origin+'/api'});
  }
  if(p==='/drive-sync/key' && request.method==='DELETE'){
    await env.DB.prepare('UPDATE drive_sync_keys SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL').bind(now(),user.id).run();
    return json({ok:true});
  }
  if(p==='/admin/accounts' && request.method==='POST'){
    if(!isAdminUser(env,user)) return json({detail:'No autorizado'},403);
    const d=await request.json().catch(()=>({}));
    const email=String(d.email||'').trim().toLowerCase();
    const password=String(d.password||'');
    const name=String(d.name||'').trim()||'Contador';
    if(!email || !password) return json({detail:'Email y contraseña son obligatorios'},400);
    const existing=await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
    if(existing) return json({detail:'Ya existe una cuenta con ese correo'},409);
    const userId=id();
    await env.DB.prepare('INSERT INTO users VALUES (?,?,?,?,?)').bind(userId,name,email,await hashPassword(password),now()).run();
    return json({ok:true,user:{id:userId,name,email},password});
  }
  if(p==='/admin/accounts' && request.method==='GET'){
    if(!isAdminUser(env,user)) return json({detail:'No autorizado'},403);
    const rows=(await env.DB.prepare('SELECT u.id, u.name, u.email, u.created_at, (SELECT COUNT(*) FROM companies c WHERE c.owner_user_id=u.id) as company_count FROM users u ORDER BY u.created_at DESC').all()).results||[];
    return json(rows);
  }
  { const mm=p.match(/^\/admin\/accounts\/([^/]+)\/reset-password$/); if(mm && request.method==='POST'){
    if(!isAdminUser(env,user)) return json({detail:'No autorizado'},403);
    const d=await request.json().catch(()=>({}));
    const password=String(d.password||'');
    if(!password) return json({detail:'La contraseña es obligatoria'},400);
    const target=await env.DB.prepare('SELECT id,email FROM users WHERE id=?').bind(mm[1]).first();
    if(!target) return json({detail:'Cuenta no encontrada'},404);
    await env.DB.prepare('UPDATE users SET password_hash=? WHERE id=?').bind(await hashPassword(password), mm[1]).run();
    await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(mm[1]).run();
    return json({ok:true,email:target.email,password});
  }}
  { const mm=p.match(/^\/companies\/([^/]+)\/siigo-test$/); if(mm && request.method==='POST'){
    const company=await ensureCompany(env,user.id,mm[1]);
    const authResult=await siigoAuth(siigoEnvFor(env,company));
    return json({ok:true, message:'Conexión con Siigo correcta', expires_in:authResult.expires_in, token_type:authResult.token_type, scope:authResult.scope});
  }}
  { const mm=p.match(/^\/companies\/([^/]+)\/siigo-catalogs$/); if(mm && request.method==='GET'){
    const company=await ensureCompany(env,user.id,mm[1]);
    const senv=siigoEnvFor(env,company);
    const result={ok:true,catalogs:{}};
    const docTypes={};
    for(const type of ['FC','FV','DS','NC','RC']){
      try{ docTypes[type]=await siigoRequest(senv,`/document-types?type=${encodeURIComponent(type)}`); }
      catch(e){ docTypes[type]={error:e.message}; }
    }
    result.catalogs.document_types=docTypes;
    try{ result.catalogs.taxes=await siigoRequest(senv,'/taxes'); }catch(e){ result.catalogs.taxes_error=e.message; }
    const paymentTypes={};
    for(const type of ['FC','FV','DS','NC','RC']){
      try{ paymentTypes[type]=await siigoRequest(senv,`/payment-types?document_type=${encodeURIComponent(type)}`); }
      catch(e){ paymentTypes[type]={error:e.message}; }
    }
    result.catalogs.payment_types=paymentTypes;
    return json(result);
  }}
  { const mm=p.match(/^\/companies\/([^/]+)\/siigo-credentials$/); if(mm && request.method==='PUT'){
    const company=await ensureCompany(env,user.id,mm[1]);
    const d=await request.json().catch(()=>({}));
    const siigoUsername=String(d.siigo_username||'').trim();
    const siigoAccessKey=String(d.siigo_access_key||'').trim();
    await env.DB.prepare('UPDATE companies SET siigo_username=?, siigo_access_key=? WHERE id=?').bind(siigoUsername||null, siigoAccessKey||company.siigo_access_key||null, mm[1]).run();
    const updated=await env.DB.prepare('SELECT * FROM companies WHERE id=?').bind(mm[1]).first();
    return json(publicCompany(updated));
  }}
  { const mm=p.match(/^\/companies\/([^/]+)\/siigo-upload-selected$/); if(mm && request.method==='POST'){
    const company=await ensureCompany(env,user.id,mm[1]);
    const senv=siigoEnvFor(env,company);
    const body=await request.json().catch(()=>({}));
    const invoiceIds=Array.isArray(body.invoice_ids)?body.invoice_ids.map(String).filter(Boolean):[];
    if(!invoiceIds.length) return json({ok:false,count:0,errors:[{error:'No seleccionaste facturas para subir a Siigo'}]},400);
    const uploaded=[], errors=[], blocked=[];
    for(const invoiceId of invoiceIds){
      let inv=null, locked=false, sent=false, attempted=false;
      try{
        inv=await env.DB.prepare('SELECT * FROM invoices WHERE id=? AND company_id=?').bind(invoiceId,mm[1]).first();
        if(!inv) throw new Error('La factura no pertenece a la empresa activa');
        // 1) Control de duplicados: nunca se envía dos veces la misma factura a Siigo.
        const prior=await findPriorExport(env, mm[1], inv);
        if(prior || isExportedStatus(inv.status)){
          const msg=prior ? priorExportMessage(prior)
            : inv.status==='exporting' ? 'Hay un envío a Siigo en curso o interrumpido para esta factura. Verifica en Siigo si quedó creada antes de volver a intentarlo.'
            : 'La factura ya está marcada como exportada. No se envía de nuevo para evitar duplicados.';
          // Si se borró y se volvió a cargar, la factura se marca de nuevo como exportada en la bandeja.
          if(prior && !isExportedStatus(inv.status)) await env.DB.prepare("UPDATE invoices SET status='exported', updated_at=? WHERE id=?").bind(now(),invoiceId).run();
          await recordExport(env, user, inv, {status:'blocked', message:msg});
          blocked.push({id:invoiceId, invoice_number:inv.invoice_number||'', supplier:inv.supplier_name||'', error:msg});
          continue;
        }
        // 2) Solo se exporta una contabilización revisada y confirmada por el usuario.
        const {entry,lines}=await entryWithLines(env, invoiceId);
        if(!entry || entry.status!=='approved' || inv.status!=='approved') throw new Error('La contabilización no ha sido confirmada. Ábrela en "Revisar contabilización", verifícala y presiona "Confirmar" antes de exportar.');
        const v=await validateEntry(env, inv, lines);
        if(!v.ok) throw new Error('La contabilización tiene errores: '+v.errors.join(' | '));
        // 3) Bloqueo: si dos envíos llegan al tiempo, solo uno pasa de 'approved' a 'exporting'.
        const lock=await env.DB.prepare("UPDATE invoices SET status='exporting', updated_at=? WHERE id=? AND status='approved'").bind(now(),invoiceId).run();
        if(!(Number(lock.meta?.changes||0)>0)) throw new Error('La factura cambió de estado mientras se preparaba el envío. Actualiza la bandeja e intenta de nuevo.');
        locked=true; attempted=true;
        const built=await buildSiigoPurchasePayload(senv, inv, lines);
        const result=await siigoRequest(senv,'/purchases',{method:'POST',body:JSON.stringify(built.payload)});
        sent=true;
        await env.DB.prepare("UPDATE invoices SET status='exported', updated_at=? WHERE id=?").bind(now(),invoiceId).run();
        locked=false;
        const total=built.payload.payments?.[0]?.value ?? inv.payable_amount;
        await recordExport(env, user, inv, {status:'success', siigo_id:result?.id, siigo_name:result?.name, total, message:`Factura de compra creada en Siigo${result?.name?` (${result.name})`:''}${built.supplier?.created?'. Se creó el proveedor en Siigo':''}`});
        await auditLog(env, user, inv, 'export', {siigo_id:result?.id||null, siigo_name:result?.name||null, total});
        uploaded.push({invoice_id:invoiceId, invoice_number:inv.invoice_number, siigo_id:result?.id||null, siigo_name:result?.name||null, supplier:built.supplier});
      }catch(e){
        if(locked){
          // Si Siigo ya respondió OK, la factura sí quedó creada: se deja como exportada aunque falle algo después.
          try{ await env.DB.prepare(`UPDATE invoices SET status=?, updated_at=? WHERE id=? AND status='exporting'`).bind(sent?'exported':'approved', now(), invoiceId).run(); }catch(_){ }
        }
        if(inv && attempted){
          try{ await recordExport(env, user, inv, sent ? {status:'success', message:'Creada en Siigo, pero hubo un error al registrar el resultado: '+e.message} : {status:'error', message:e.message}); }catch(_){ }
        }
        errors.push({id:invoiceId, invoice_number:inv?.invoice_number||'', supplier:inv?.supplier_name||'', nit:inv?.supplier_nit||'', error:e.message});
      }
    }
    return json({ok:uploaded.length>0, count:uploaded.length, uploaded, errors, blocked});
  }}
  if(p==='/companies' && request.method==='GET'){ const rows=(await env.DB.prepare('SELECT * FROM companies WHERE owner_user_id=? ORDER BY created_at DESC').bind(user.id).all()).results||[]; return json(rows.map(publicCompany)); }
  if(p==='/companies' && request.method==='POST'){ const d=await request.json(); const companyId=id(); await env.DB.prepare('INSERT INTO companies (id,owner_user_id,name,nit,created_at) VALUES (?,?,?,?,?)').bind(companyId,user.id,d.name,nitClean(d.nit),now()).run(); await env.DB.prepare('INSERT INTO accounting_settings (company_id) VALUES (?)').bind(companyId).run(); for(const r of [['supplier','CLARO','51353501','Servicios públicos - Teléfono','Administración',10],['supplier','CLASSIC JEANS','51952501','Elementos de aseo y cafetería','Administración',35],['default','*','52959505','Gastos diversos POS','Administración',999]]) await env.DB.prepare('INSERT INTO accounting_rules VALUES (?,?,?,?,?,?,?,?,?,?)').bind(id(),companyId,r[0],r[1],r[2],r[3],r[4],r[5],1,now()).run(); return json(publicCompany(await env.DB.prepare('SELECT * FROM companies WHERE id=?').bind(companyId).first())); }
  let m=p.match(/^\/companies\/([^/]+)$/); if(m && request.method==='PUT'){
    await ensureCompany(env,user.id,m[1]);
    const d=await request.json();
    const name=String(d.name||'').trim();
    const nit=nitClean(d.nit);
    if(!name) throw new Error('El nombre de la empresa es obligatorio');
    if(!nit) throw new Error('El NIT de la empresa es obligatorio');
    const other=await env.DB.prepare('SELECT id FROM companies WHERE owner_user_id=? AND nit=? AND id<>?').bind(user.id,nit,m[1]).first();
    if(other) throw new Error('Ya existe otra empresa con ese NIT');
    await env.DB.prepare('UPDATE companies SET name=?, nit=? WHERE id=? AND owner_user_id=?').bind(name,nit,m[1],user.id).run();
    return json(publicCompany(await env.DB.prepare('SELECT * FROM companies WHERE id=?').bind(m[1]).first()));
  }
  m=p.match(/^\/companies\/([^/]+)$/); if(m && request.method==='DELETE'){
    await ensureCompany(env,user.id,m[1]);
    await env.DB.prepare('DELETE FROM accounting_entry_lines WHERE entry_id IN (SELECT e.id FROM accounting_entries e JOIN invoices i ON i.id=e.invoice_id WHERE i.company_id=?)').bind(m[1]).run();
    await env.DB.prepare('DELETE FROM accounting_entries WHERE invoice_id IN (SELECT id FROM invoices WHERE company_id=?)').bind(m[1]).run();
    await env.DB.prepare('DELETE FROM invoice_items WHERE invoice_id IN (SELECT id FROM invoices WHERE company_id=?)').bind(m[1]).run();
    await env.DB.prepare('DELETE FROM invoices WHERE company_id=?').bind(m[1]).run();
    await env.DB.prepare('DELETE FROM accounting_rules WHERE company_id=?').bind(m[1]).run();
    await env.DB.prepare('DELETE FROM accounting_settings WHERE company_id=?').bind(m[1]).run();
    await ensureExtraSchema(env);
    await env.DB.prepare('DELETE FROM import_logs WHERE company_id=?').bind(m[1]).run();
    await env.DB.prepare('DELETE FROM dian_sync_logs WHERE company_id=?').bind(m[1]).run();
    await env.DB.prepare('DELETE FROM dian_connections WHERE company_id=?').bind(m[1]).run();
    await env.DB.prepare('DELETE FROM siigo_exports WHERE company_id=?').bind(m[1]).run();
    await env.DB.prepare('DELETE FROM entry_audit_log WHERE company_id=?').bind(m[1]).run();
    await env.DB.prepare('DELETE FROM invoice_pdfs WHERE company_id=?').bind(m[1]).run();
    await env.DB.prepare('DELETE FROM companies WHERE id=? AND owner_user_id=?').bind(m[1],user.id).run();
    return json({ok:true, deleted:m[1]});
  }
  m=p.match(/^\/companies\/([^/]+)\/settings$/); if(m && request.method==='GET'){ await ensureCompany(env,user.id,m[1]); return json(await getSettings(env,m[1])); }
  if(m && request.method==='PUT'){
    await ensureCompany(env,user.id,m[1]); await ensureExtraSchema(env);
    const d=await request.json();
    await validateAccountCode(env,m[1],d.vat_account,'Cuenta IVA 19%');
    await validateAccountCode(env,m[1],d.vat5_account,'Cuenta IVA 5%');
    await validateAccountCode(env,m[1],d.payable_account,'Cuenta proveedores');
    await validateAccountCode(env,m[1],d.withholding_account,'Cuenta retención');
    await validateAccountCode(env,m[1],d.default_expense_account,'Cuenta de gasto por defecto');
    await env.DB.prepare('UPDATE accounting_settings SET vat_account=?, vat_description=?, vat5_account=?, vat5_description=?, payable_account=?, payable_description=?, withholding_account=?, withholding_description=?, default_cost_center=?, default_expense_account=?, default_expense_description=? WHERE company_id=?').bind(d.vat_account,d.vat_description,d.vat5_account,d.vat5_description,d.payable_account,d.payable_description,d.withholding_account,d.withholding_description,d.default_cost_center,d.default_expense_account,d.default_expense_description,m[1]).run();
    return json(await getSettings(env,m[1]));
  }
  m=p.match(/^\/companies\/([^/]+)\/rules$/); if(m && request.method==='GET'){ await ensureCompany(env,user.id,m[1]); return json((await env.DB.prepare('SELECT * FROM accounting_rules WHERE company_id=? ORDER BY priority').bind(m[1]).all()).results||[]); }
  if(m && request.method==='POST'){
    await ensureCompany(env,user.id,m[1]); await ensureExtraSchema(env);
    const d=await request.json();
    await validateAccountCode(env,m[1],d.account,'La cuenta de la regla');
    const rid=id();
    await env.DB.prepare('INSERT INTO accounting_rules VALUES (?,?,?,?,?,?,?,?,?,?)').bind(rid,m[1],d.match_type,d.match_value,d.account,d.description,d.cost_center||'',d.priority||100,1,now()).run();
    return json(await env.DB.prepare('SELECT * FROM accounting_rules WHERE id=?').bind(rid).first());
  }
  m=p.match(/^\/companies\/([^/]+)\/chart-of-accounts$/); if(m && request.method==='GET'){
    await ensureCompany(env,user.id,m[1]); await ensureExtraSchema(env);
    const q=url.searchParams.get('q')||''; const onlyActive=url.searchParams.get('active')!=='0';
    let sql='SELECT code, name, category, clase, active, level FROM chart_of_accounts WHERE company_id=?'; const args=[m[1]];
    if(onlyActive){ sql+=' AND active=1'; }
    if(q){ sql+=' AND (code LIKE ? OR name LIKE ?)'; args.push(`%${q}%`,`%${q}%`); }
    sql+=' ORDER BY code LIMIT 500';
    const rows=(await env.DB.prepare(sql).bind(...args).all()).results||[];
    return json(rows);
  }
  if(m && request.method==='POST'){
    await ensureCompany(env,user.id,m[1]); await ensureExtraSchema(env);
    const fd=await request.formData();
    const file=fd.get('file');
    if(!file) return json({detail:'Sube un archivo CSV con el plan de cuentas (columnas: codigo,nombre,categoria,clase,activo,nivel)'},400);
    const text=await file.text();
    const rows=parseAccountsCsv(text);
    if(!rows.length) return json({detail:'El CSV no tiene filas de cuentas válidas'},400);
    let imported=0;
    for(const r of rows){
      await env.DB.prepare('INSERT INTO chart_of_accounts (id, company_id, code, name, category, clase, active, level, created_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(company_id, code) DO UPDATE SET name=excluded.name, category=excluded.category, clase=excluded.clase, active=excluded.active, level=excluded.level')
        .bind(id(), m[1], r.code, r.name, r.category, r.clase, r.active, r.level, now()).run();
      imported++;
    }
    const total=await env.DB.prepare('SELECT COUNT(*) c, SUM(active) a FROM chart_of_accounts WHERE company_id=?').bind(m[1]).first();
    return json({ok:true, imported, total_accounts:total?.c||0, active_accounts:total?.a||0});
  }
  m=p.match(/^\/companies\/([^/]+)\/invoices$/); if(m && request.method==='GET'){ await ensureCompany(env,user.id,m[1]); return json((await env.DB.prepare('SELECT invoices.*, EXISTS(SELECT 1 FROM invoice_pdfs p WHERE p.invoice_id=invoices.id) AS has_pdf FROM invoices WHERE company_id=? ORDER BY issue_date DESC').bind(m[1]).all()).results||[]); }
  { const mm=p.match(/^\/companies\/([^/]+)\/batches$/); if(mm && request.method==='GET'){
    await ensureCompany(env,user.id,mm[1]);
    return json(await listBatches(env,mm[1]));
  }}
  { const mm=p.match(/^\/companies\/([^/]+)\/batches$/); if(mm && request.method==='POST'){
    await ensureCompany(env,user.id,mm[1]);
    const d=await request.json().catch(()=>({}));
    const name=String(d.name||'').trim();
    if(!name) return json({detail:'El centro de facturas necesita un nombre'},400);
    const batchId=id();
    await env.DB.prepare('INSERT INTO invoice_batches (id,company_id,name,created_at) VALUES (?,?,?,?)').bind(batchId,mm[1],name,now()).run();
    return json({id:batchId,company_id:mm[1],name,created_at:now()});
  }}
  { const mm=p.match(/^\/companies\/([^/]+)\/batches\/([^/]+)$/); if(mm && request.method==='PUT'){
    await ensureCompany(env,user.id,mm[1]);
    const d=await request.json().catch(()=>({}));
    const name=String(d.name||'').trim();
    if(!name) return json({detail:'El nombre no puede quedar vacío'},400);
    await env.DB.prepare('UPDATE invoice_batches SET name=? WHERE id=? AND company_id=?').bind(name,mm[2],mm[1]).run();
    return json({ok:true});
  }}
  m=p.match(/^\/companies\/([^/]+)\/upload$/); if(m && request.method==='POST'){
    const company=await ensureCompany(env,user.id,m[1]);
    const fd=await request.formData();
    // auto_month=1: cada factura nueva va al centro de su mes de emisión ("Octubre 2026"), creándolo si no existe.
    // Sin esa opción, todo va al centro activo (comportamiento anterior).
    const autoMonth=String(fd.get('auto_month')||'')==='1';
    const batchId=autoMonth ? null : await resolveBatchId(env, m[1], fd.get('batch_id'));
    const imported=[], errors=[];
    async function processOne(name, xml){
      const parsed=await parseInvoice(xml);
      const batchName=autoMonth ? monthBatchName([], parsed.issue_date) : null;
      const targetBatch=autoMonth ? await batchByName(env, m[1], batchName) : batchId;
      if(nitClean(parsed.customer_nit)!==nitClean(company.nit)) throw new Error(`Factura rechazada: receptor ${parsed.customer_nit} no coincide con empresa ${company.nit}`);
      const invoiceId=id();
      const exists=await env.DB.prepare('SELECT id,status FROM invoices WHERE company_id=? AND cufe=?').bind(m[1],parsed.cufe).first();
      if(exists && isExportedStatus(exists.status)) throw new Error(`Factura ${parsed.invoice_number}: ya fue exportada a Siigo; no se reemplaza para no perder el control de duplicados`);
      const finalId=exists?.id||invoiceId;
      if(exists) await env.DB.prepare('DELETE FROM invoice_items WHERE invoice_id=?').bind(finalId).run();
      if(exists) await env.DB.prepare('UPDATE invoices SET invoice_number=?, issue_date=?, document_type=?, supplier_name=?, supplier_nit=?, customer_name=?, customer_nit=?, currency=?, subtotal=?, tax_amount=?, withholding_amount=?, payable_amount=?, status=?, raw_xml=?, updated_at=?, tax_breakdown=? WHERE id=?').bind(parsed.invoice_number,parsed.issue_date,parsed.document_type,parsed.supplier_name,parsed.supplier_nit,parsed.customer_name,parsed.customer_nit,parsed.currency,parsed.subtotal,parsed.tax_amount,parsed.withholding_amount,parsed.payable_amount,'received',parsed.invoice_xml,now(),JSON.stringify(parsed.tax_breakdown||{}),finalId).run();
      else await env.DB.prepare('INSERT INTO invoices (id,company_id,invoice_number,cufe,issue_date,document_type,supplier_name,supplier_nit,customer_name,customer_nit,currency,subtotal,tax_amount,withholding_amount,payable_amount,status,raw_xml,created_at,updated_at,tax_breakdown,batch_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(finalId,m[1],parsed.invoice_number,parsed.cufe,parsed.issue_date,parsed.document_type,parsed.supplier_name,parsed.supplier_nit,parsed.customer_name,parsed.customer_nit,parsed.currency,parsed.subtotal,parsed.tax_amount,parsed.withholding_amount,parsed.payable_amount,'received',parsed.invoice_xml,now(),now(),JSON.stringify(parsed.tax_breakdown||{}),targetBatch).run();
      for(const it of parsed.items) await env.DB.prepare('INSERT INTO invoice_items VALUES (?,?,?,?,?)').bind(id(),finalId,it.description,it.quantity,it.line_amount).run();
      imported.push({file:name, invoice_id:finalId, invoice_number:parsed.invoice_number, batch:batchName, existed:!!exists});
    }
    const zipNotices=[];
    for(const file of fd.getAll('file')){
      try{
        const lower=(file.name||'').toLowerCase();
        if(lower.endsWith('.zip')){
          const entries=await extractZipEntries(await file.arrayBuffer());
          if(!entries.length){
            const detail=zipStatsMessage(entries.stats);
            errors.push({file:file.name,error: detail ? `El ZIP no contiene XML/HTML/TXT procesable. ${detail}. Si solo contiene PDF, descarga desde DIAN el XML de las facturas.` : 'El ZIP no contiene XML/HTML/TXT procesable'});
            continue;
          }
          zipNotices.push(`${file.name}: ${zipStatsMessage(entries.stats)}`);
          for(const entry of entries){
            if(entry._error){ errors.push({file:entry.name,error:entry._error}); continue; }
            try{ await processOne(entry.name, entry.text); }
            catch(e){ errors.push({file:entry.name,error:e.message}); }
          }
        }else{
          await processOne(file.name, await file.text());
        }
      }catch(e){ errors.push({file:file.name,error:e.message}); }
    }
    // PDF que acompaña al XML (la pantalla lo envía junto al XML de la misma factura dentro del ZIP).
    const pdfFile=fd.get('pdf');
    if(pdfFile && typeof pdfFile!=='string' && imported.length===1){
      try{
        const r=await storeInvoicePdf(env,{id:imported[0].invoice_id,company_id:m[1]},pdfFile.name,bytesToB64(new Uint8Array(await pdfFile.arrayBuffer())),'carga',true);
        imported[0].pdf=r.ok?'guardado':r.error;
        if(!r.ok) errors.push({file:pdfFile.name,error:r.error});
      }catch(e){ errors.push({file:pdfFile.name,error:'No pude guardar el PDF: '+e.message}); }
    }
    await ensureExtraSchema(env);
    const status = errors.length && imported.length ? 'partial' : errors.length ? 'error' : 'success';
    const fileNames = [...fd.getAll('file')].map(f=>f.name).join(', ');
    await env.DB.prepare('INSERT INTO import_logs VALUES (?,?,?,?,?,?,?,?)').bind(id(), m[1], fileNames, status, imported.length, errors.length, JSON.stringify({imported,errors}), now()).run();
    return json({imported,errors,zip_notices:zipNotices});
  }
  // Factura que solo viene en PDF: la pantalla lee el PDF, el usuario revisa los datos y aquí se crea la factura.
  m=p.match(/^\/companies\/([^/]+)\/pdf-invoice$/); if(m && request.method==='POST'){
    const company=await ensureCompany(env,user.id,m[1]);
    const fd=await request.formData();
    let d={}; try{ d=JSON.parse(String(fd.get('data')||'{}')); }catch(_){ return json({detail:'Datos inválidos'},400); }
    const pdfFile=fd.get('file');
    const number=String(d.invoice_number||'').trim().slice(0,60);
    const date=String(d.issue_date||'').trim();
    const supplierNit=nitClean(d.supplier_nit);
    const supplierName=String(d.supplier_name||'').trim().slice(0,200);
    const total=round2(Number(d.payable_amount)||0), tax=round2(Number(d.tax_amount)||0);
    let subtotal=round2(Number(d.subtotal)||0);
    const missing=[]; if(!number)missing.push('número de factura'); if(!/^\d{4}-\d{2}-\d{2}$/.test(date))missing.push('fecha (AAAA-MM-DD)'); if(!supplierNit)missing.push('NIT del proveedor'); if(!(total>0))missing.push('total');
    if(missing.length) return json({detail:'Faltan datos: '+missing.join(', ')},400);
    if(!(subtotal>0)) subtotal=round2(total-tax);
    const cufeRaw=String(d.cufe||'').replace(/[^0-9a-f]/gi,'').toLowerCase();
    const cufe=cufeRaw.length>=64 ? cufeRaw : `pdf-${supplierNit}-${number.toUpperCase()}`;
    const pdfB64=(pdfFile && typeof pdfFile!=='string') ? bytesToB64(new Uint8Array(await pdfFile.arrayBuffer())) : '';
    // Si la factura ya existe (mismo CUFE o mismo NIT + número), no se duplica: solo se le guarda el PDF si no tenía.
    const exists=await env.DB.prepare('SELECT id,invoice_number FROM invoices WHERE company_id=? AND (cufe=? OR (supplier_nit=? AND upper(invoice_number)=?))').bind(m[1],cufe,supplierNit,number.toUpperCase()).first();
    if(exists){
      let pdf='';
      if(pdfB64){ const r=await storeInvoicePdf(env,{id:exists.id,company_id:m[1]},pdfFile.name,pdfB64,'pdf',false); pdf=r.ok?'guardado':r.error; }
      return json({status:'duplicate', invoice_id:exists.id, invoice_number:exists.invoice_number, pdf});
    }
    // IVA por tarifa (se deduce del valor); retención implícita si el total es menor que subtotal + IVA (igual que con XML).
    const breakdown={};
    if(tax>0 && subtotal>0){ const pct=tax/subtotal*100; const near=[19,5].find(t=>Math.abs(pct-t)<=1.2); breakdown[String(near||Math.round(pct))]=tax; }
    let withholding=round2(Number(d.withholding_amount)||0);
    const implied=round2(subtotal+tax-total); if(!withholding && implied>0.5) withholding=implied;
    const autoMonth=String(fd.get('auto_month')||'')==='1';
    const batchName=autoMonth ? monthBatchName([], date) : null;
    const batchId=autoMonth ? await batchByName(env,m[1],batchName) : await resolveBatchId(env,m[1],fd.get('batch_id'));
    const invId=id();
    await env.DB.batch([
      env.DB.prepare('INSERT INTO invoices (id,company_id,invoice_number,cufe,issue_date,document_type,supplier_name,supplier_nit,customer_name,customer_nit,currency,subtotal,tax_amount,withholding_amount,payable_amount,status,raw_xml,created_at,updated_at,tax_breakdown,batch_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
        .bind(invId,m[1],number,cufe,date,'Factura compra (PDF)',supplierName||`Proveedor ${supplierNit}`,supplierNit,company.name,company.nit,'COP',subtotal,tax,withholding,total,'received',null,now(),now(),JSON.stringify(breakdown),batchId),
      env.DB.prepare('INSERT INTO invoice_items VALUES (?,?,?,?,?)').bind(id(),invId,String(d.description||`Factura ${number} (importada desde PDF)`).slice(0,250),1,subtotal)
    ]);
    let pdf='';
    if(pdfB64){ const r=await storeInvoicePdf(env,{id:invId,company_id:m[1]},pdfFile.name,pdfB64,'pdf',true); pdf=r.ok?'guardado':r.error; }
    await ensureExtraSchema(env);
    await env.DB.prepare('INSERT INTO import_logs VALUES (?,?,?,?,?,?,?,?)').bind(id(), m[1], pdfFile?.name||'PDF', 'success', 1, 0, JSON.stringify({imported:[{invoice_number:number, source:'pdf'}],errors:[]}), now()).run();
    return json({status:'imported', invoice_id:invId, invoice_number:number, batch:batchName, pdf});
  }
  m=p.match(/^\/invoices\/([^/]+)$/); if(m && request.method==='GET'){
    const inv=await ensureInvoice(env,user,m[1]);
    const items=(await env.DB.prepare('SELECT * FROM invoice_items WHERE invoice_id=?').bind(m[1]).all()).results||[];
    const {entry,lines}=await entryWithLines(env,m[1]);
    const validation=entry ? await validateEntry(env,inv,lines) : null;
    const exports=(await env.DB.prepare("SELECT * FROM siigo_exports WHERE company_id=? AND (invoice_id=? OR (cufe<>'' AND cufe=?)) ORDER BY created_at DESC LIMIT 50").bind(inv.company_id,inv.id,inv.cufe||'').all()).results||[];
    const audit=(await env.DB.prepare('SELECT * FROM entry_audit_log WHERE invoice_id=? ORDER BY created_at DESC LIMIT 100').bind(m[1]).all()).results||[];
    const pdf=await env.DB.prepare('SELECT file_name,size,source,created_at FROM invoice_pdfs WHERE invoice_id=?').bind(m[1]).first();
    return json({invoice:inv,items,entry,lines,validation,exports,audit,pdf:pdf||null});
  }
  m=p.match(/^\/invoices\/([^/]+)\/pdf$/); if(m && request.method==='GET'){
    await ensureInvoice(env,user,m[1]);
    const row=await env.DB.prepare('SELECT file_name,content_b64 FROM invoice_pdfs WHERE invoice_id=?').bind(m[1]).first();
    if(!row) return json({detail:'Esta factura no tiene PDF original guardado'},404);
    const safe=String(row.file_name||'factura.pdf').replace(/[^\w.\- ]+/g,'_');
    return new Response(b64ToBytes(row.content_b64),{headers:{'content-type':'application/pdf','content-disposition':`attachment; filename="${safe}"`,...corsHeaders}});
  }
  if(m && request.method==='POST'){
    const inv=await ensureInvoice(env,user,m[1]);
    const fd=await request.formData();
    const file=fd.get('file');
    if(!file || typeof file==='string') return json({detail:'Adjunta un archivo PDF'},400);
    const r=await storeInvoicePdf(env,inv,file.name,bytesToB64(new Uint8Array(await file.arrayBuffer())),'manual',true);
    if(!r.ok) return json({detail:r.error},400);
    return json({ok:true,size:r.size});
  }
  if(m && request.method==='DELETE'){
    await ensureInvoice(env,user,m[1]);
    await env.DB.prepare('DELETE FROM invoice_pdfs WHERE invoice_id=?').bind(m[1]).run();
    return json({ok:true});
  }
  m=p.match(/^\/invoices\/([^/]+)\/generate-entry$/); if(m && request.method==='POST'){
    const inv=await ensureInvoice(env,user,m[1]);
    if(isExportedStatus(inv.status)) return json({detail:'La factura ya fue exportada a Siigo; su contabilización no se puede recalcular.'},409);
    const current=await env.DB.prepare('SELECT edited FROM accounting_entries WHERE invoice_id=?').bind(m[1]).first();
    if(current?.edited && url.searchParams.get('force')!=='1') return json({detail:'Esta contabilización tiene correcciones manuales. Para descartarlas y recalcularla, usa "Recalcular automática" dentro de la revisión.'},409);
    return json(await generateEntry(env,m[1],user));
  }
  m=p.match(/^\/invoices\/([^/]+)\/approve$/); if(m && request.method==='POST'){
    let inv=await ensureInvoice(env,user,m[1]);
    if(isExportedStatus(inv.status)) return json({detail:'La factura ya fue exportada a Siigo.'},409);
    let {entry,lines}=await entryWithLines(env,m[1]);
    if(!entry){ await generateEntry(env,m[1],user); inv=await ensureInvoice(env,user,m[1]); ({entry,lines}=await entryWithLines(env,m[1])); }
    const validation=await validateEntry(env,inv,lines);
    if(!validation.ok) return json({detail:`Factura ${inv.invoice_number}: no se puede confirmar. `+validation.errors.join(' | '), validation},400);
    await env.DB.batch([
      env.DB.prepare("UPDATE accounting_entries SET status='approved', approved_at=?, reviewed_by=? WHERE id=?").bind(now(),user.email||'',entry.id),
      env.DB.prepare("UPDATE invoices SET status='approved', updated_at=? WHERE id=?").bind(now(),m[1])
    ]);
    await auditLog(env,user,inv,'approve',{warnings:validation.warnings,totals:validation.totals});
    return json({ok:true, validation});
  }
  m=p.match(/^\/invoices\/([^/]+)\/entry$/); if(m && request.method==='PUT'){
    const inv=await ensureInvoice(env,user,m[1]);
    if(isExportedStatus(inv.status)) return json({detail:'La factura ya fue exportada a Siigo; su contabilización no se puede modificar.'},409);
    const d=await request.json().catch(()=>({}));
    const reason=String(d.reason||'').trim().slice(0,500);
    const newLines=(Array.isArray(d.lines)?d.lines:[]).map(l=>({
      account:String(l.account||'').trim(),
      description:String(l.description||'').trim().slice(0,250),
      debit:round2(Number(l.debit||0)), credit:round2(Number(l.credit||0)),
      cost_center:String(l.cost_center||'').trim().slice(0,100)
    })).filter(l=>l.account||l.description||l.debit||l.credit);
    if(newLines.length>60) return json({detail:'Máximo 60 líneas por asiento'},400);
    const validation=await validateEntry(env,inv,newLines);
    if(!validation.ok) return json({detail:'No se guardó: '+validation.errors.join(' | '), validation},400);
    const before=await entryWithLines(env,m[1]);
    const entryId=before.entry?.id || id();
    const stmts=[];
    if(before.entry){
      stmts.push(env.DB.prepare("UPDATE accounting_entries SET status='suggested', approved_at=NULL, reviewed_by=NULL, edited=1 WHERE id=?").bind(entryId));
      stmts.push(env.DB.prepare('DELETE FROM accounting_entry_lines WHERE entry_id=?').bind(entryId));
    } else {
      stmts.push(env.DB.prepare("INSERT INTO accounting_entries (id,invoice_id,status,confidence,created_at,approved_at,edited) VALUES (?,?,'suggested',1,?,NULL,1)").bind(entryId,m[1],now()));
    }
    for(const l of newLines) stmts.push(env.DB.prepare('INSERT INTO accounting_entry_lines (id,entry_id,account,description,debit,credit,cost_center) VALUES (?,?,?,?,?,?,?)').bind(id(),entryId,l.account,l.description||'Sin descripción',l.debit,l.credit,l.cost_center));
    stmts.push(env.DB.prepare("UPDATE invoices SET status='accounted', updated_at=? WHERE id=?").bind(now(),m[1]));
    await env.DB.batch(stmts);
    await auditLog(env,user,inv,'edit',{before:simpleLines(before.lines), after:newLines, reason});
    const after=await entryWithLines(env,m[1]);
    return json({ok:true, entry:after.entry, lines:after.lines, validation:await validateEntry(env,inv,after.lines)});
  }
  m=p.match(/^\/companies\/([^/]+)\/siigo-exports$/); if(m && request.method==='GET'){
    await ensureCompany(env,user.id,m[1]);
    let sql='SELECT * FROM siigo_exports WHERE company_id=?'; const args=[m[1]];
    const st=url.searchParams.get('status'); if(st && st!=='all'){ sql+=' AND status=?'; args.push(st); }
    const from=url.searchParams.get('from'); if(from){ sql+=' AND created_at>=?'; args.push(from); }
    // "to" puede ser una fecha (AAAA-MM-DD, incluye todo el día) o un instante exacto en ISO (lo envía el Dashboard).
    const to=url.searchParams.get('to'); if(to){ sql+=' AND created_at<=?'; args.push(to.includes('T')?to:to+'T99'); }
    const q=String(url.searchParams.get('q')||'').trim(); if(q){ sql+=' AND (invoice_number LIKE ? OR supplier_name LIKE ? OR supplier_nit LIKE ? OR cufe LIKE ? OR siigo_name LIKE ?)'; for(let i=0;i<5;i++) args.push(`%${q}%`); }
    const lim=Math.min(2000,Math.max(1,parseInt(url.searchParams.get('limit')||'2000',10)||2000));
    sql+=` ORDER BY created_at DESC LIMIT ${lim}`;
    return json((await env.DB.prepare(sql).bind(...args).all()).results||[]);
  }
  m=p.match(/^\/companies\/([^/]+)\/audit-log$/); if(m && request.method==='GET'){
    await ensureCompany(env,user.id,m[1]);
    let sql='SELECT * FROM entry_audit_log WHERE company_id=?'; const args=[m[1]];
    const q=String(url.searchParams.get('q')||'').trim(); if(q){ sql+=' AND (invoice_number LIKE ? OR user_email LIKE ?)'; args.push(`%${q}%`,`%${q}%`); }
    sql+=' ORDER BY created_at DESC LIMIT 1000';
    return json((await env.DB.prepare(sql).bind(...args).all()).results||[]);
  }
  m=p.match(/^\/companies\/([^/]+)\/report$/); if(m && request.method==='POST'){
    await ensureCompany(env,user.id,m[1]);
    const body=await request.json().catch(()=>({}));
    const ids=(Array.isArray(body.invoice_ids)?body.invoice_ids.map(String).filter(Boolean):[]).slice(0,80);
    if(!ids.length) return json([]);
    const ph=ids.map(()=>'?').join(',');
    const invs=(await env.DB.prepare(`SELECT id,company_id,invoice_number,cufe,issue_date,document_type,supplier_name,supplier_nit,customer_name,customer_nit,subtotal,tax_amount,withholding_amount,payable_amount,status FROM invoices WHERE company_id=? AND id IN (${ph})`).bind(m[1],...ids).all()).results||[];
    const entries=(await env.DB.prepare(`SELECT * FROM accounting_entries WHERE invoice_id IN (${ph})`).bind(...ids).all()).results||[];
    const entryIds=entries.map(e=>e.id);
    const lines=entryIds.length ? ((await env.DB.prepare(`SELECT * FROM accounting_entry_lines WHERE entry_id IN (${entryIds.map(()=>'?').join(',')}) ORDER BY rowid`).bind(...entryIds).all()).results||[]) : [];
    const exps=(await env.DB.prepare(`SELECT invoice_id,status,siigo_name,created_at,user_email FROM siigo_exports WHERE company_id=? AND status='success' AND invoice_id IN (${ph}) ORDER BY created_at DESC`).bind(m[1],...ids).all()).results||[];
    const out=invs.map(inv=>{
      const e=entries.find(x=>x.invoice_id===inv.id)||null;
      return {invoice:inv, entry:e, lines:e?lines.filter(l=>l.entry_id===e.id):[], export:exps.find(x=>x.invoice_id===inv.id)||null};
    });
    out.sort((a,b)=>ids.indexOf(a.invoice.id)-ids.indexOf(b.invoice.id));
    return json(out);
  }
  m=p.match(/^\/companies\/([^/]+)\/dian-connection$/); if(m && request.method==='GET'){
    await ensureCompany(env,user.id,m[1]); await ensureExtraSchema(env);
    const row=await env.DB.prepare('SELECT company_id, person_type, representative_id_type, representative_id, company_nit, token_last4, start_date, status, last_test_at, last_sync_at, created_at, updated_at FROM dian_connections WHERE company_id=?').bind(m[1]).first();
    return json(row||null);
  }
  if(m && request.method==='POST'){
    const company=await ensureCompany(env,user.id,m[1]); await ensureExtraSchema(env); const d=await request.json();
    const parsed=parseDianAuthUrl(d.token_url);
    const nit=nitClean(d.company_nit||company.nit);
    if(nitClean(company.nit)!==nit) throw new Error('El NIT de conexión DIAN no coincide con la empresa activa');
    const existing=await env.DB.prepare('SELECT company_id FROM dian_connections WHERE company_id=?').bind(m[1]).first();
    if(existing) await env.DB.prepare('UPDATE dian_connections SET person_type=?, representative_id_type=?, representative_id=?, company_nit=?, token_url=?, token_last4=?, start_date=?, status=?, updated_at=? WHERE company_id=?').bind(d.person_type||'juridica',d.representative_id_type||'CC',d.representative_id||'',nit,parsed.url,parsed.last4,d.start_date||'', 'saved', now(), m[1]).run();
    else await env.DB.prepare('INSERT INTO dian_connections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(m[1],d.person_type||'juridica',d.representative_id_type||'CC',d.representative_id||'',nit,parsed.url,parsed.last4,d.start_date||'', 'saved', null, null, now(), now()).run();
    return json({ok:true, token_last4:parsed.last4, message:'Conexión DIAN guardada'});
  }
  m=p.match(/^\/companies\/([^/]+)\/dian-test$/); if(m && request.method==='POST'){
    await ensureCompany(env,user.id,m[1]); await ensureExtraSchema(env);
    const conn=await env.DB.prepare('SELECT * FROM dian_connections WHERE company_id=?').bind(m[1]).first(); if(!conn) throw new Error('Primero guarda la conexión DIAN');
    const result=await testDianTokenUrl(conn.token_url);
    await env.DB.prepare('UPDATE dian_connections SET status=?, last_test_at=?, updated_at=? WHERE company_id=?').bind(result.format_ok?'tested':'error', now(), now(), m[1]).run();
    return json(result);
  }
  m=p.match(/^\/companies\/([^/]+)\/dian-sync$/); if(m && request.method==='POST'){
    await ensureCompany(env,user.id,m[1]); await ensureExtraSchema(env);
    const conn=await env.DB.prepare('SELECT * FROM dian_connections WHERE company_id=?').bind(m[1]).first(); if(!conn) throw new Error('Primero guarda la conexión DIAN (pega el token de acceso)');
    const body=await request.json().catch(()=>({}));
    const method=body.method==='cufes' ? 'cufes' : 'fechas';
    const cufes=method==='cufes' ? (Array.isArray(body.cufes)?body.cufes:String(body.cufes||'').split(/[\s,;]+/)).map(s=>String(s||'').trim()).filter(Boolean) : [];
    if(method==='cufes' && !cufes.length) throw new Error('Ingresa al menos un CUFE para buscar');
    const startDate=body.start_date || conn.start_date || new Date(Date.now()-30*24*3600*1000).toISOString().slice(0,10);
    const endDate=body.end_date || new Date().toISOString().slice(0,10);
    let docs=[], status='error', errorMsg='';
    try{
      docs=await fetchDianReceivedDocuments(conn.token_url, method==='fechas' ? {mode:'fechas', start_date:startDate, end_date:endDate} : {mode:'cufes', cufes});
      status='success';
    }catch(e){ errorMsg=e.message; status='error'; }
    const existing=(await env.DB.prepare('SELECT cufe FROM invoices WHERE company_id=?').bind(m[1]).all()).results||[];
    const knownSet=new Set(existing.map(r=>String(r.cufe||'').toUpperCase()));
    for(const d of docs) d.already_in_contapilot = knownSet.has(String(d.id||'').toUpperCase());
    const resultSummary={method, start_date:startDate, end_date:endDate, cufes, found:docs.length, error:errorMsg};
    await env.DB.prepare('INSERT INTO dian_sync_logs VALUES (?,?,?,?,?,?,?)').bind(id(),m[1],status,JSON.stringify(resultSummary),docs.length,errorMsg?1:0,now()).run();
    await env.DB.prepare('UPDATE dian_connections SET status=?, last_sync_at=?, updated_at=? WHERE company_id=?').bind(status,now(),now(),m[1]).run();
    if(status==='error') return json({ok:false, error:errorMsg}, 400);
    return json({ok:true, found:docs.length, documents:docs});
  }
  m=p.match(/^\/companies\/([^/]+)\/dian-logs$/); if(m && request.method==='GET'){
    await ensureCompany(env,user.id,m[1]); await ensureExtraSchema(env);
    const rows=(await env.DB.prepare('SELECT * FROM dian_sync_logs WHERE company_id=? ORDER BY created_at DESC LIMIT 50').bind(m[1]).all()).results||[];
    return json(rows);
  }
  m=p.match(/^\/companies\/([^/]+)\/import-logs$/); if(m && request.method==='GET'){
    await ensureCompany(env,user.id,m[1]);
    await ensureExtraSchema(env);
    const rows=(await env.DB.prepare('SELECT * FROM import_logs WHERE company_id=? ORDER BY created_at DESC LIMIT 100').bind(m[1]).all()).results||[];
    return json(rows);
  }
  m=p.match(/^\/companies\/([^/]+)\/delete-invoices$/); if(m && request.method==='POST'){
    await ensureCompany(env,user.id,m[1]);
    const body=await request.json().catch(()=>({}));
    const invoiceIds=Array.isArray(body.invoice_ids)?body.invoice_ids.map(String).filter(Boolean):[];
    if(!invoiceIds.length) return json({ok:false, count:0, errors:[{error:'No seleccionaste facturas para eliminar'}]},400);
    let count=0, errors=[];
    for(const invoiceId of invoiceIds){
      try{
        const inv=await env.DB.prepare('SELECT id, invoice_number FROM invoices WHERE id=? AND company_id=?').bind(invoiceId,m[1]).first();
        if(!inv) throw new Error('La factura no pertenece a la empresa activa');
        await env.DB.prepare('DELETE FROM accounting_entry_lines WHERE entry_id IN (SELECT id FROM accounting_entries WHERE invoice_id=?)').bind(invoiceId).run();
        await env.DB.prepare('DELETE FROM accounting_entries WHERE invoice_id=?').bind(invoiceId).run();
        await env.DB.prepare('DELETE FROM invoice_items WHERE invoice_id=?').bind(invoiceId).run();
        await env.DB.prepare('DELETE FROM invoice_pdfs WHERE invoice_id=?').bind(invoiceId).run();
        await env.DB.prepare('DELETE FROM invoices WHERE id=? AND company_id=?').bind(invoiceId,m[1]).run();
        count++;
      }catch(e){ errors.push({id:invoiceId, error:e.message}); }
    }
    return json({ok:!errors.length || count>0, count, errors});
  }
  m=p.match(/^\/companies\/([^/]+)\/cause-selected$/); if(m && request.method==='POST'){
    await ensureCompany(env,user.id,m[1]);
    const body=await request.json().catch(()=>({}));
    const invoiceIds=Array.isArray(body.invoice_ids)?body.invoice_ids.map(String).filter(Boolean):[];
    if(!invoiceIds.length) return json({ok:false, count:0, errors:[{error:'No seleccionaste facturas'}]},400);
    let count=0, errors=[];
    for(const invoiceId of invoiceIds){
      try{
        const inv=await env.DB.prepare('SELECT i.id,i.status,i.invoice_number,e.edited FROM invoices i LEFT JOIN accounting_entries e ON e.invoice_id=i.id WHERE i.id=? AND i.company_id=?').bind(invoiceId,m[1]).first();
        if(!inv) throw new Error('La factura no pertenece a la empresa activa');
        if(isExportedStatus(inv.status)) throw new Error(`Factura ${inv.invoice_number}: ya está exportada a Siigo y no se recausa`);
        if(inv.edited) throw new Error(`Factura ${inv.invoice_number}: tiene correcciones manuales y no se recausa automáticamente. Usa "Recalcular automática" dentro de la revisión si quieres descartarlas.`);
        await generateEntry(env, invoiceId, user);
        count++;
      }catch(e){ errors.push({id:invoiceId, error:e.message}); }
    }
    return json({ok:!errors.length || count>0, count, errors});
  }
  m=p.match(/^\/companies\/([^/]+)\/cause-all$/); if(m && request.method==='POST'){
    await ensureCompany(env,user.id,m[1]);
    const pending=(await env.DB.prepare("SELECT i.id FROM invoices i LEFT JOIN accounting_entries e ON e.invoice_id=i.id WHERE i.company_id=? AND i.status='received' AND COALESCE(e.edited,0)=0").bind(m[1]).all()).results||[];
    if(!pending.length) return json({ok:true, count:0, message:'No hay facturas pendientes de causación'});
    let count=0, errors=[];
    for(const inv of pending){
      try{ await generateEntry(env, inv.id, user); count++; }
      catch(e){ errors.push({id:inv.id, error:e.message}); }
    }
    return json({ok:true, count, errors});
  }
  m=p.match(/^\/companies\/([^/]+)\/mark-exported$/); if(m && request.method==='POST'){
    await ensureCompany(env,user.id,m[1]);
    // Solo se marcan las facturas con contabilización confirmada, y cada una queda en el historial
    // para que después no se pueda volver a enviar a Siigo por API (sería un duplicado).
    const body=await request.json().catch(()=>({}));
    const onlyIds=Array.isArray(body.invoice_ids)?body.invoice_ids.map(String).filter(Boolean):null;
    let rows=(await env.DB.prepare("SELECT * FROM invoices WHERE company_id=? AND status='approved'").bind(m[1]).all()).results||[];
    if(onlyIds) rows=rows.filter(r=>onlyIds.includes(r.id));
    let changed=0;
    for(const inv of rows.slice(0,200)){
      const r=await env.DB.prepare("UPDATE invoices SET status='exported', updated_at=? WHERE id=? AND status='approved'").bind(now(),inv.id).run();
      if(Number(r.meta?.changes||0)>0){
        changed++;
        await recordExport(env, user, inv, {channel:'csv', status:'success', message:'Marcada como exportada al descargar el CSV (no se envió por API).'});
        await auditLog(env, user, inv, 'export', {channel:'csv'});
      }
    }
    return json({ok:true, changed});
  }
  m=p.match(/^\/companies\/([^/]+)\/export\.csv$/); if(m && request.method==='GET'){
    await ensureCompany(env,user.id,m[1]);
    const format=url.searchParams.get('format')||'general';
    const rows=(await env.DB.prepare('SELECT i.*, l.account, l.description line_description, l.debit, l.credit, l.cost_center FROM invoices i LEFT JOIN accounting_entries e ON e.invoice_id=i.id LEFT JOIN accounting_entry_lines l ON l.entry_id=e.id WHERE i.company_id=? ORDER BY i.issue_date DESC, i.invoice_number, l.debit DESC').bind(m[1]).all()).results||[];
    const lineRows=rows.filter(r=>r.account);
    if(format==='siigo'){
      // Plantilla Base Siigo según captura del contador.
      // Como solo conocemos columnas S-AA, dejamos A-R como columnas vacías para conservar posiciones.
      // S: Código activo fijo
      // T: Descripción
      // U: Código centro/subcentro de costos
      // V: Débito
      // W: Crédito
      // X: Observaciones
      // Y: Base gravable libro compras/ventas
      // Z: Base exenta libro compras/ventas
      // AA: Mes de cierre
      const headers=[
        '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '',
        'Código activo fijo','Descripción','Código centro/subcentro de costos','Débito','Crédito','Observaciones','Base gravable libro compras/ventas','Base exenta libro compras/ventas','Mes de cierre'
      ];
      const out=[headers.map(csvCell).join(';')];
      for(const r of lineRows){
        const account=String(r.account||'');
        const desc=String(r.line_description||'');
        const upperDesc=desc.toUpperCase();
        const isVat=account==='24081001' || account==='240805' || account==='240810' || upperDesc.includes('IVA');
        const isWithholding=account.startsWith('2365') || upperDesc.includes('RETEN');
        const hasTax=Number(r.tax_amount||0)>0;
        let baseGravable=0;
        let baseExenta=0;
        if(isVat || isWithholding) baseGravable=Number(r.subtotal||0);
        if(!hasTax && Number(r.debit||0)>0 && !isVat && !isWithholding) baseExenta=Number(r.subtotal||0);
        const observacion=[`Factura ${r.invoice_number||''}`, r.issue_date?`Fecha ${r.issue_date}`:''].filter(Boolean).join(' | ');
        const row=[
          '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '',
          '',
          desc,
          r.cost_center||'',
          moneyPlain(r.debit),
          moneyPlain(r.credit),
          observacion,
          moneyPlain(baseGravable),
          moneyPlain(baseExenta),
          monthFromDate(r.issue_date)
        ];
        out.push(row.map(csvCell).join(';'));
      }
      return text(out.join('\n'),200,'text/csv; charset=utf-8');
    }
    const csv=['factura;fecha;proveedor;nit;cufe;cuenta;descripcion;debito;credito;centro_costo;estado',...lineRows.map(r=>[r.invoice_number,r.issue_date,r.supplier_name,r.supplier_nit,r.cufe,r.account,r.line_description,r.debit,r.credit,r.cost_center,r.status].map(csvCell).join(';'))].join('\n');
    return text(csv,200,'text/csv; charset=utf-8');
  }
  return json({detail:'Ruta no encontrada'},404);
}catch(e){ if(e instanceof Response) return e; return json({detail:e.message||String(e)},500); }}



async function saveParsedInvoiceForCompany(env, company, parsed, sourceName='email'){
  if(nitClean(parsed.customer_nit)!==nitClean(company.nit)) throw new Error(`Factura rechazada: receptor ${parsed.customer_nit} no coincide con empresa ${company.nit}`);
  const exists=await env.DB.prepare('SELECT id,status FROM invoices WHERE company_id=? AND cufe=?').bind(company.id, parsed.cufe).first();
  if(exists && isExportedStatus(exists.status)) throw new Error(`Factura ${parsed.invoice_number}: ya fue exportada a Siigo; no se reemplaza`);
  const finalId=exists?.id || id();
  if(exists){
    await env.DB.prepare('DELETE FROM invoice_items WHERE invoice_id=?').bind(finalId).run();
    await env.DB.prepare('DELETE FROM accounting_entry_lines WHERE entry_id IN (SELECT id FROM accounting_entries WHERE invoice_id=?)').bind(finalId).run().catch(()=>{});
    await env.DB.prepare('DELETE FROM accounting_entries WHERE invoice_id=?').bind(finalId).run().catch(()=>{});
    await env.DB.prepare('UPDATE invoices SET invoice_number=?, issue_date=?, document_type=?, supplier_name=?, supplier_nit=?, customer_name=?, customer_nit=?, currency=?, subtotal=?, tax_amount=?, withholding_amount=?, payable_amount=?, status=?, raw_xml=?, updated_at=?, tax_breakdown=? WHERE id=?').bind(parsed.invoice_number,parsed.issue_date,parsed.document_type,parsed.supplier_name,parsed.supplier_nit,parsed.customer_name,parsed.customer_nit,parsed.currency,parsed.subtotal,parsed.tax_amount,parsed.withholding_amount,parsed.payable_amount,'received',parsed.invoice_xml,now(),JSON.stringify(parsed.tax_breakdown||{}),finalId).run();
  }else{
    const batchId=await resolveBatchId(env, company.id, null);
    await env.DB.prepare('INSERT INTO invoices (id,company_id,invoice_number,cufe,issue_date,document_type,supplier_name,supplier_nit,customer_name,customer_nit,currency,subtotal,tax_amount,withholding_amount,payable_amount,status,raw_xml,created_at,updated_at,tax_breakdown,batch_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(finalId,company.id,parsed.invoice_number,parsed.cufe,parsed.issue_date,parsed.document_type,parsed.supplier_name,parsed.supplier_nit,parsed.customer_name,parsed.customer_nit,parsed.currency,parsed.subtotal,parsed.tax_amount,parsed.withholding_amount,parsed.payable_amount,'received',parsed.invoice_xml,now(),now(),JSON.stringify(parsed.tax_breakdown||{}),batchId).run();
  }
  for(const it of parsed.items) await env.DB.prepare('INSERT INTO invoice_items VALUES (?,?,?,?,?)').bind(id(),finalId,it.description,it.quantity,it.line_amount).run();
  return {file:sourceName, invoice_id:finalId, invoice_number:parsed.invoice_number};
}
function decodeBase64ToBytes(b64){ const bin=atob(String(b64||'').replace(/\s/g,'')); const bytes=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i); return bytes; }
function parseEmailAttachments(raw){
  const out=[]; const header=raw.split(/\r?\n\r?\n/)[0]||''; const bm=header.match(/boundary="?([^";\r\n]+)"?/i); if(!bm) return out; const boundary=bm[1]; const parts=raw.split('--'+boundary);
  for(const part of parts){
    const [h,...rest]=part.split(/\r?\n\r?\n/); if(!rest.length) continue; const body=rest.join('\n\n').replace(/\r?\n--$/,'');
    const filename=(h.match(/filename\*?=(?:UTF-8''|\")?([^";\r\n]+)/i)||h.match(/name\*?=(?:UTF-8''|\")?([^";\r\n]+)/i)||[])[1];
    if(!filename) continue; const cleanName=decodeURIComponent(filename.replace(/"/g,'').trim()); const lower=cleanName.toLowerCase();
    if(!['.xml','.html','.htm','.txt','.zip'].some(ext=>lower.endsWith(ext))) continue;
    const enc=(h.match(/content-transfer-encoding:\s*([^\r\n]+)/i)||[])[1]?.toLowerCase()||'';
    let bytes, textContent;
    if(enc.includes('base64')){ bytes=decodeBase64ToBytes(body); if(!lower.endsWith('.zip')) textContent=new TextDecoder('utf-8').decode(bytes); }
    else { textContent=body.trim(); bytes=new TextEncoder().encode(textContent); }
    out.push({name:cleanName, bytes, text:textContent});
  }
  return out;
}
async function processIncomingEmail(message, env){
  await ensureExtraSchema(env);
  const to=message.to || message.headers?.get?.('to') || ''; const digits=nitClean((String(to).match(/[0-9]{6,}/)||[])[0]||'');
  if(!digits){ await message.setReject('El correo receptor debe incluir el NIT de la empresa, por ejemplo 1002249038@tu-dominio.com'); return; }
  const company=await env.DB.prepare('SELECT * FROM companies WHERE nit=? LIMIT 1').bind(digits).first();
  if(!company){ await message.setReject(`No existe empresa configurada para NIT ${digits}`); return; }
  const raw=await new Response(message.raw).text(); const attachments=parseEmailAttachments(raw); const imported=[], errors=[];
  for(const att of attachments){
    try{
      if(att.name.toLowerCase().endsWith('.zip')){
        const buf=att.bytes.buffer.slice(att.bytes.byteOffset, att.bytes.byteOffset+att.bytes.byteLength);
        const entries=await extractZipEntries(buf);
        for(const entry of entries){ if(entry._error){ errors.push({file:entry.name,error:entry._error}); continue; } try{ imported.push(await saveParsedInvoiceForCompany(env, company, await parseInvoice(entry.text), entry.name)); }catch(e){ errors.push({file:entry.name,error:e.message}); } }
      }else imported.push(await saveParsedInvoiceForCompany(env, company, await parseInvoice(att.text), att.name));
    }catch(e){ errors.push({file:att.name,error:e.message}); }
  }
  const status=errors.length&&imported.length?'partial':errors.length?'error':'success';
  await env.DB.prepare('INSERT INTO import_logs VALUES (?,?,?,?,?,?,?,?)').bind(id(), company.id, `email:${message.from||''}`, status, imported.length, errors.length, JSON.stringify({imported,errors,from:message.from,to}), now()).run();
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api')) {
      return handleApi(request, env);
    }
    return env.ASSETS.fetch(request);
  },
  async email(message, env, ctx) {
    ctx.waitUntil(processIncomingEmail(message, env));
  }
};
