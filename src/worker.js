const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8' }
});
const text = (data, status = 200, type = 'text/plain; charset=utf-8') => new Response(data, { status, headers: { 'content-type': type }});
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
function u16(bytes,pos){ return bytes[pos] | (bytes[pos+1] << 8); }
function u32(bytes,pos){ return (bytes[pos] | (bytes[pos+1] << 8) | (bytes[pos+2] << 16) | (bytes[pos+3] << 24)) >>> 0; }
async function inflateRaw(bytes){
  if(typeof DecompressionStream === 'undefined') throw new Error('Este entorno no soporta descompresión ZIP automática. Sube el XML descomprimido.');
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
async function extractZipEntries(arrayBuffer){
  const bytes = new Uint8Array(arrayBuffer);
  let eocd = -1;
  for(let i=bytes.length-22; i>=0 && i>bytes.length-66000; i--){ if(u32(bytes,i)===0x06054b50){ eocd=i; break; } }
  if(eocd < 0) throw new Error('No pude leer el ZIP. Puede estar dañado o protegido.');
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
    const lower=name.toLowerCase();
    if(!lower.endsWith('.xml') && !lower.endsWith('.html') && !lower.endsWith('.htm') && !lower.endsWith('.txt')) continue;
    if(u32(bytes,localOffset)!==0x04034b50) continue;
    const ln=u16(bytes,localOffset+26), le=u16(bytes,localOffset+28);
    const dataStart=localOffset+30+ln+le;
    const compressed=bytes.slice(dataStart, dataStart+compSize);
    let contentBytes;
    if(method===0) contentBytes=compressed;
    else if(method===8) contentBytes=await inflateRaw(compressed);
    else throw new Error(`El archivo ${name} usa compresión ZIP no soportada: ${method}`);
    entries.push({name, text:decoder.decode(contentBytes)});
  }
  return entries;
}

function party(xml, partyTag){ const re=new RegExp(`<(?:\\w+:)?${partyTag}\\b[\\s\\S]*?<\/(?:\\w+:)?${partyTag}>`,'i'); const block=(xml.match(re)||[''])[0]; let name=tagText(block,'RegistrationName') || tagText(block,'Name'); let nit=tagText(block,'CompanyID') || tagText(block,'ID'); return {name,nit}; }
async function parseInvoice(input){ const xml=extractInvoiceXml(input); const root=(xml.match(/<(?:\w+:)?(Invoice|CreditNote|DebitNote)\b/i)||[])[1] || 'Invoice'; const supplier=party(xml,'AccountingSupplierParty'); const customer=party(xml,'AccountingCustomerParty'); const invoiceNumber=tagText(xml,'ID'); const cufe=tagText(xml,'UUID') || await sha256(xml); const issueDate=tagText(xml,'IssueDate'); const currency=tagText(xml,'DocumentCurrencyCode') || 'COP'; const monetary=(xml.match(/<(?:\w+:)?LegalMonetaryTotal\b[\s\S]*?<\/(?:\w+:)?LegalMonetaryTotal>/i)||[''])[0]; const subtotal=num(tagText(monetary,'TaxExclusiveAmount') || tagText(monetary,'LineExtensionAmount')); const payable=num(tagText(monetary,'PayableAmount') || tagText(monetary,'TaxInclusiveAmount')) || subtotal; let tax=0; for(const m of xml.matchAll(/<(?:\w+:)?TaxTotal\b[\s\S]*?<\/(?:\w+:)?TaxTotal>/gi)){ tax += num(tagText(m[0],'TaxAmount')); } let withholding=0; for(const m of xml.matchAll(/<(?:\w+:)?WithholdingTaxTotal\b[\s\S]*?<\/(?:\w+:)?WithholdingTaxTotal>/gi)){ withholding += num(tagText(m[0],'TaxAmount')); } const lineTag=root==='CreditNote'?'CreditNoteLine':root==='DebitNote'?'DebitNoteLine':'InvoiceLine'; const qtyTag=root==='CreditNote'?'CreditedQuantity':root==='DebitNote'?'DebitedQuantity':'InvoicedQuantity'; const items=[]; const lineRe=new RegExp(`<(?:\\w+:)?${lineTag}\\b[\\s\\S]*?<\\/(?:\\w+:)?${lineTag}>`,'gi'); for(const m of xml.matchAll(lineRe)){ items.push({description:tagText(m[0],'Description'), quantity:num(tagText(m[0],qtyTag)), line_amount:num(tagText(m[0],'LineExtensionAmount'))}); } return {invoice_xml:xml, invoice_number:invoiceNumber, cufe, issue_date:issueDate, document_type:root==='Invoice'?'Factura compra':root==='CreditNote'?'Nota crédito':'Nota débito', supplier_name:supplier.name, supplier_nit:supplier.nit, customer_name:customer.name, customer_nit:customer.nit, currency, subtotal, tax_amount:tax, withholding_amount:withholding, payable_amount:payable, items}; }
async function auth(env, request){ const h=request.headers.get('authorization')||''; if(!h.toLowerCase().startsWith('bearer ')) throw new Response(JSON.stringify({detail:'Falta token Authorization: Bearer'}),{status:401}); const token=h.split(' ')[1]; const row=await env.DB.prepare('SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=?').bind(token).first(); if(!row) throw new Response(JSON.stringify({detail:'Sesión inválida'}),{status:401}); return row; }
async function ensureCompany(env,userId,companyId){ const c=await env.DB.prepare('SELECT * FROM companies WHERE id=? AND owner_user_id=?').bind(companyId,userId).first(); if(!c) throw new Response(JSON.stringify({detail:'Empresa no encontrada'}),{status:404}); return c; }
async function getSettings(env, companyId){ return await env.DB.prepare('SELECT * FROM accounting_settings WHERE company_id=?').bind(companyId).first(); }
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
async function chooseRule(env, companyId, inv){ const rules=(await env.DB.prepare('SELECT * FROM accounting_rules WHERE company_id=? AND active=1 ORDER BY priority').bind(companyId).all()).results || []; const text=((inv.supplier_name||'')+' '+(inv.descriptions||'')).toUpperCase(); let fallback=null; for(const r of rules){ if(r.match_type==='default'){fallback=r; continue;} if(text.includes(String(r.match_value||'').toUpperCase())) return r; } return fallback; }
async function generateEntry(env, invoiceId){ const inv=await env.DB.prepare('SELECT * FROM invoices WHERE id=?').bind(invoiceId).first(); if(!inv) throw new Error('Factura no encontrada'); const settings=await getSettings(env, inv.company_id); const items=(await env.DB.prepare('SELECT * FROM invoice_items WHERE invoice_id=?').bind(invoiceId).all()).results||[]; inv.descriptions=items.map(i=>i.description||'').join(' '); const rule=await chooseRule(env, inv.company_id, inv); let entry=await env.DB.prepare('SELECT * FROM accounting_entries WHERE invoice_id=?').bind(invoiceId).first(); let entryId=entry?.id || id(); if(entry){ await env.DB.prepare('DELETE FROM accounting_entry_lines WHERE entry_id=?').bind(entryId).run(); await env.DB.prepare("UPDATE accounting_entries SET status='suggested', confidence=?, created_at=?, approved_at=NULL WHERE id=?").bind(.88, now(), entryId).run(); } else { await env.DB.prepare('INSERT INTO accounting_entries VALUES (?,?,?,?,?,?)').bind(entryId, invoiceId, 'suggested', .88, now(), null).run(); }
  const add=(account,description,debit,credit,cost='')=>env.DB.prepare('INSERT INTO accounting_entry_lines VALUES (?,?,?,?,?,?,?)').bind(id(), entryId, account, description, Number(debit||0), Number(credit||0), cost).run();
  await add(rule?.account || settings.default_expense_account, rule?.description || settings.default_expense_description, inv.subtotal, 0, rule?.cost_center || settings.default_cost_center);
  if(inv.tax_amount) await add(settings.vat_account, settings.vat_description, inv.tax_amount, 0, '');
  if(inv.withholding_amount) await add(settings.withholding_account, settings.withholding_description, 0, inv.withholding_amount, '');
  await add(settings.payable_account, `${settings.payable_description} - ${inv.supplier_name||''}`, 0, inv.payable_amount, '');
  await env.DB.prepare("UPDATE invoices SET status='accounted', updated_at=? WHERE id=?").bind(now(), invoiceId).run();
  const lines=(await env.DB.prepare('SELECT * FROM accounting_entry_lines WHERE entry_id=?').bind(entryId).all()).results||[]; entry=await env.DB.prepare('SELECT * FROM accounting_entries WHERE id=?').bind(entryId).first(); return {entry,lines}; }
async function handleApi(request, env){ const url=new URL(request.url); const p=url.pathname.replace(/^\/api/,'') || '/'; try{
  if(request.method==='OPTIONS') return new Response(null,{status:204});
  if(p==='/health') return json({ok:true, service:'contapilot-cloudflare', time:now()});
  if(p==='/auth/register' && request.method==='POST'){ const d=await request.json(); const userId=id(); const token=id()+id(); await env.DB.prepare('INSERT INTO users VALUES (?,?,?,?,?)').bind(userId,d.name||'Contador Demo',String(d.email||'').toLowerCase(),await hashPassword(d.password||''),now()).run(); await env.DB.prepare('INSERT INTO sessions VALUES (?,?,?)').bind(token,userId,now()).run(); return json({token,user:{id:userId,name:d.name||'Contador Demo',email:String(d.email||'').toLowerCase()}}); }
  if(p==='/auth/login' && request.method==='POST'){ const d=await request.json(); const u=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(String(d.email||'').toLowerCase()).first(); if(!u || !(await verifyPassword(d.password||'', u.password_hash))) return json({detail:'Correo o contraseña inválidos'},401); const token=id()+id(); await env.DB.prepare('INSERT INTO sessions VALUES (?,?,?)').bind(token,u.id,now()).run(); return json({token,user:{id:u.id,name:u.name,email:u.email}}); }
  const user=await auth(env,request);
  if(p==='/companies' && request.method==='GET'){ const rows=(await env.DB.prepare('SELECT * FROM companies WHERE owner_user_id=? ORDER BY created_at DESC').bind(user.id).all()).results||[]; return json(rows); }
  if(p==='/companies' && request.method==='POST'){ const d=await request.json(); const companyId=id(); await env.DB.prepare('INSERT INTO companies VALUES (?,?,?,?,?)').bind(companyId,user.id,d.name,nitClean(d.nit),now()).run(); await env.DB.prepare('INSERT INTO accounting_settings (company_id) VALUES (?)').bind(companyId).run(); for(const r of [['supplier','CLARO','513535','Gasto telecomunicaciones','Administración',10],['supplier','CLASSIC JEANS','519525','Vestuario / dotación','Administración',35],['default','*','519595','Gastos diversos','Administración',999]]) await env.DB.prepare('INSERT INTO accounting_rules VALUES (?,?,?,?,?,?,?,?,?,?)').bind(id(),companyId,r[0],r[1],r[2],r[3],r[4],r[5],1,now()).run(); return json(await env.DB.prepare('SELECT * FROM companies WHERE id=?').bind(companyId).first()); }
  let m=p.match(/^\/companies\/([^/]+)\/settings$/); if(m && request.method==='GET'){ await ensureCompany(env,user.id,m[1]); return json(await getSettings(env,m[1])); }
  if(m && request.method==='PUT'){ await ensureCompany(env,user.id,m[1]); const d=await request.json(); await env.DB.prepare('UPDATE accounting_settings SET vat_account=?, vat_description=?, payable_account=?, payable_description=?, withholding_account=?, withholding_description=?, default_cost_center=?, default_expense_account=?, default_expense_description=? WHERE company_id=?').bind(d.vat_account,d.vat_description,d.payable_account,d.payable_description,d.withholding_account,d.withholding_description,d.default_cost_center,d.default_expense_account,d.default_expense_description,m[1]).run(); return json(await getSettings(env,m[1])); }
  m=p.match(/^\/companies\/([^/]+)\/rules$/); if(m && request.method==='GET'){ await ensureCompany(env,user.id,m[1]); return json((await env.DB.prepare('SELECT * FROM accounting_rules WHERE company_id=? ORDER BY priority').bind(m[1]).all()).results||[]); }
  if(m && request.method==='POST'){ await ensureCompany(env,user.id,m[1]); const d=await request.json(); const rid=id(); await env.DB.prepare('INSERT INTO accounting_rules VALUES (?,?,?,?,?,?,?,?,?,?)').bind(rid,m[1],d.match_type,d.match_value,d.account,d.description,d.cost_center||'',d.priority||100,1,now()).run(); return json(await env.DB.prepare('SELECT * FROM accounting_rules WHERE id=?').bind(rid).first()); }
  m=p.match(/^\/companies\/([^/]+)\/invoices$/); if(m && request.method==='GET'){ await ensureCompany(env,user.id,m[1]); return json((await env.DB.prepare('SELECT * FROM invoices WHERE company_id=? ORDER BY issue_date DESC').bind(m[1]).all()).results||[]); }
  m=p.match(/^\/companies\/([^/]+)\/upload$/); if(m && request.method==='POST'){
    const company=await ensureCompany(env,user.id,m[1]);
    const fd=await request.formData();
    const imported=[], errors=[];
    async function processOne(name, xml){
      const parsed=await parseInvoice(xml);
      if(nitClean(parsed.customer_nit)!==nitClean(company.nit)) throw new Error(`Factura rechazada: receptor ${parsed.customer_nit} no coincide con empresa ${company.nit}`);
      const invoiceId=id();
      const exists=await env.DB.prepare('SELECT id FROM invoices WHERE company_id=? AND cufe=?').bind(m[1],parsed.cufe).first();
      const finalId=exists?.id||invoiceId;
      if(exists) await env.DB.prepare('DELETE FROM invoice_items WHERE invoice_id=?').bind(finalId).run();
      if(exists) await env.DB.prepare('UPDATE invoices SET invoice_number=?, issue_date=?, document_type=?, supplier_name=?, supplier_nit=?, customer_name=?, customer_nit=?, currency=?, subtotal=?, tax_amount=?, withholding_amount=?, payable_amount=?, status=?, raw_xml=?, updated_at=? WHERE id=?').bind(parsed.invoice_number,parsed.issue_date,parsed.document_type,parsed.supplier_name,parsed.supplier_nit,parsed.customer_name,parsed.customer_nit,parsed.currency,parsed.subtotal,parsed.tax_amount,parsed.withholding_amount,parsed.payable_amount,'received',parsed.invoice_xml,now(),finalId).run();
      else await env.DB.prepare('INSERT INTO invoices VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(finalId,m[1],parsed.invoice_number,parsed.cufe,parsed.issue_date,parsed.document_type,parsed.supplier_name,parsed.supplier_nit,parsed.customer_name,parsed.customer_nit,parsed.currency,parsed.subtotal,parsed.tax_amount,parsed.withholding_amount,parsed.payable_amount,'received',parsed.invoice_xml,now(),now()).run();
      for(const it of parsed.items) await env.DB.prepare('INSERT INTO invoice_items VALUES (?,?,?,?,?)').bind(id(),finalId,it.description,it.quantity,it.line_amount).run();
      imported.push({file:name, invoice_id:finalId, invoice_number:parsed.invoice_number});
    }
    for(const file of fd.getAll('file')){
      try{
        const lower=(file.name||'').toLowerCase();
        if(lower.endsWith('.zip')){
          const entries=await extractZipEntries(await file.arrayBuffer());
          if(!entries.length){ errors.push({file:file.name,error:'El ZIP no contiene XML/HTML/TXT procesable'}); continue; }
          for(const entry of entries){
            try{ await processOne(entry.name, entry.text); }
            catch(e){ errors.push({file:entry.name,error:e.message}); }
          }
        }else{
          await processOne(file.name, await file.text());
        }
      }catch(e){ errors.push({file:file.name,error:e.message}); }
    }
    await ensureExtraSchema(env);
    const status = errors.length && imported.length ? 'partial' : errors.length ? 'error' : 'success';
    const fileNames = [...fd.getAll('file')].map(f=>f.name).join(', ');
    await env.DB.prepare('INSERT INTO import_logs VALUES (?,?,?,?,?,?,?,?)').bind(id(), m[1], fileNames, status, imported.length, errors.length, JSON.stringify({imported,errors}), now()).run();
    return json({imported,errors});
  }
  m=p.match(/^\/invoices\/([^/]+)$/); if(m && request.method==='GET'){
    const inv=await env.DB.prepare('SELECT * FROM invoices WHERE id=?').bind(m[1]).first();
    if(!inv) return json({detail:'Factura no encontrada'},404);
    const items=(await env.DB.prepare('SELECT * FROM invoice_items WHERE invoice_id=?').bind(m[1]).all()).results||[];
    const entry=await env.DB.prepare('SELECT * FROM accounting_entries WHERE invoice_id=?').bind(m[1]).first();
    const lines=entry?(await env.DB.prepare('SELECT * FROM accounting_entry_lines WHERE entry_id=?').bind(entry.id).all()).results||[]:[];
    return json({invoice:inv,items,entry,lines});
  }
  m=p.match(/^\/invoices\/([^/]+)\/generate-entry$/); if(m && request.method==='POST') return json(await generateEntry(env,m[1]));
  m=p.match(/^\/invoices\/([^/]+)\/approve$/); if(m && request.method==='POST'){ const entry=await env.DB.prepare('SELECT * FROM accounting_entries WHERE invoice_id=?').bind(m[1]).first(); if(!entry) await generateEntry(env,m[1]); const e=await env.DB.prepare('SELECT * FROM accounting_entries WHERE invoice_id=?').bind(m[1]).first(); await env.DB.prepare("UPDATE accounting_entries SET status='approved', approved_at=? WHERE id=?").bind(now(),e.id).run(); await env.DB.prepare("UPDATE invoices SET status='approved', updated_at=? WHERE id=?").bind(now(),m[1]).run(); return json({ok:true}); }
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
  m=p.match(/^\/companies\/([^/]+)\/dian-session-start$/); if(m && request.method==='POST'){
    const company=await ensureCompany(env,user.id,m[1]); await ensureExtraSchema(env);
    const conn=await env.DB.prepare('SELECT * FROM dian_connections WHERE company_id=?').bind(m[1]).first(); if(!conn) throw new Error('Primero guarda la conexión DIAN');
    const serviceUrl=(env.DIAN_SYNC_SERVICE_URL||'').replace(/\/$/,''); if(!serviceUrl) throw new Error('Falta configurar DIAN_SYNC_SERVICE_URL');
    const payload={token_url:conn.token_url, company_nit:company.nit, start_date:conn.start_date||new Date(Date.now()-30*24*3600*1000).toISOString().slice(0,10), end_date:new Date().toISOString().slice(0,10), max_documents:50};
    const responseText=await fetch(`${serviceUrl}/sessions/start`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)}).then(r=>r.text().then(t=>({ok:r.ok,status:r.status,text:t})));
    let result; try{result=JSON.parse(responseText.text)}catch(_){result={text:responseText.text}}
    if(!responseText.ok) throw new Error(result.detail||result.error||('Servicio DIAN respondió '+responseText.status));
    await env.DB.prepare('INSERT INTO dian_sync_logs VALUES (?,?,?,?,?,?,?)').bind(id(),m[1],'remote_session_started',JSON.stringify(result),0,0,now()).run();
    return json(result);
  }
  m=p.match(/^\/companies\/([^/]+)\/dian-session-sync$/); if(m && request.method==='POST'){
    const company=await ensureCompany(env,user.id,m[1]); await ensureExtraSchema(env);
    const conn=await env.DB.prepare('SELECT * FROM dian_connections WHERE company_id=?').bind(m[1]).first(); if(!conn) throw new Error('Primero guarda la conexión DIAN');
    const serviceUrl=(env.DIAN_SYNC_SERVICE_URL||'').replace(/\/$/,''); if(!serviceUrl) throw new Error('Falta configurar DIAN_SYNC_SERVICE_URL');
    const body=await request.json(); if(!body.session_id) throw new Error('Falta session_id');
    const authHeader=request.headers.get('authorization')||'';
    const payload={session_id:body.session_id, company_nit:company.nit, start_date:conn.start_date||new Date(Date.now()-30*24*3600*1000).toISOString().slice(0,10), end_date:new Date().toISOString().slice(0,10), max_documents:50, contapilot_upload_url:new URL(`/api/companies/${m[1]}/upload`, request.url).toString(), contapilot_bearer_token:authHeader.replace(/^Bearer\s+/i,'')};
    const r=await fetch(`${serviceUrl}/sessions/sync`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
    const responseText=await r.text(); let result; try{result=JSON.parse(responseText)}catch(_){result={text:responseText}}
    let imported=0, errors=0; const uploads=result.upload_result?.uploads||[]; imported=uploads.reduce((a,u)=>a+((u.response?.imported||[]).length),0); errors=(result.errors||[]).length+uploads.reduce((a,u)=>a+((u.response?.errors||[]).length),0);
    const status=r.ok?(errors&&imported?'partial':errors?'error':'success'):'error';
    await env.DB.prepare('INSERT INTO dian_sync_logs VALUES (?,?,?,?,?,?,?)').bind(id(),m[1],status,JSON.stringify(result),imported,errors,now()).run();
    await env.DB.prepare('UPDATE dian_connections SET status=?, last_sync_at=?, updated_at=? WHERE company_id=?').bind(status,now(),now(),m[1]).run();
    if(!r.ok) throw new Error(result.detail||result.error||('Servicio DIAN respondió '+r.status));
    return json({ok:status==='success'||status==='partial', status, imported, errors, result});
  }
  m=p.match(/^\/companies\/([^/]+)\/dian-session-close$/); if(m && request.method==='POST'){
    await ensureCompany(env,user.id,m[1]); const serviceUrl=(env.DIAN_SYNC_SERVICE_URL||'').replace(/\/$/,''); if(!serviceUrl) throw new Error('Falta configurar DIAN_SYNC_SERVICE_URL');
    const body=await request.json(); if(!body.session_id) throw new Error('Falta session_id');
    const r=await fetch(`${serviceUrl}/sessions/${body.session_id}/close`,{method:'POST'}); const txt=await r.text(); let result; try{result=JSON.parse(txt)}catch(_){result={text:txt}}
    return json(result,r.ok?200:r.status);
  }
  m=p.match(/^\/companies\/([^/]+)\/dian-sync$/); if(m && request.method==='POST'){
    const company=await ensureCompany(env,user.id,m[1]); await ensureExtraSchema(env);
    const conn=await env.DB.prepare('SELECT * FROM dian_connections WHERE company_id=?').bind(m[1]).first(); if(!conn) throw new Error('Primero guarda la conexión DIAN');
    const serviceUrl=(env.DIAN_SYNC_SERVICE_URL||'').replace(/\/$/,'');
    if(!serviceUrl){
      const test=await testDianTokenUrl(conn.token_url);
      const msg='Conexión DIAN guardada, pero falta configurar DIAN_SYNC_SERVICE_URL para que ContaPilot llame al microservicio de sincronización.';
      await env.DB.prepare('INSERT INTO dian_sync_logs VALUES (?,?,?,?,?,?,?)').bind(id(),m[1],'missing_service',JSON.stringify({message:msg,test}),0,1,now()).run();
      return json({ok:false,status:'missing_service',message:msg,test});
    }
    const authHeader=request.headers.get('authorization')||'';
    const payload={
      token_url: conn.token_url,
      company_nit: company.nit,
      start_date: conn.start_date || new Date(Date.now()-30*24*3600*1000).toISOString().slice(0,10),
      end_date: new Date().toISOString().slice(0,10),
      max_documents: 50,
      headless: true,
      contapilot_upload_url: new URL(`/api/companies/${m[1]}/upload`, request.url).toString(),
      contapilot_bearer_token: authHeader.replace(/^Bearer\s+/i,'')
    };
    let result, status='error', imported=0, errors=0;
    try{
      const res=await fetch(`${serviceUrl}/sync`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
      const responseText=await res.text(); try{ result=JSON.parse(responseText); }catch(_){ result={text:responseText}; }
      if(!res.ok) throw new Error(result.detail||result.error||('Servicio DIAN respondió '+res.status));
      status=result.ok?'success':'partial';
      const uploads=result.upload_result?.uploads||[];
      imported=uploads.reduce((acc,u)=>acc+((u.response?.imported||[]).length),0);
      errors=(result.errors||[]).length + uploads.reduce((acc,u)=>acc+((u.response?.errors||[]).length),0);
      if(errors && imported) status='partial'; else if(errors) status='error';
    }catch(e){
      result={error:e.message}; status='error'; errors=1;
    }
    await env.DB.prepare('INSERT INTO dian_sync_logs VALUES (?,?,?,?,?,?,?)').bind(id(),m[1],status,JSON.stringify(result),imported,errors,now()).run();
    await env.DB.prepare('UPDATE dian_connections SET status=?, last_sync_at=?, updated_at=? WHERE company_id=?').bind(status,now(),now(),m[1]).run();
    return json({ok:status==='success'||status==='partial',status,imported,errors,result});
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
  m=p.match(/^\/companies\/([^/]+)\/cause-all$/); if(m && request.method==='POST'){
    await ensureCompany(env,user.id,m[1]);
    const pending=(await env.DB.prepare('SELECT id FROM invoices WHERE company_id=? AND status="received"').bind(m[1]).all()).results||[];
    if(!pending.length) return json({ok:true, count:0, message:'No hay facturas pendientes de causación'});
    let count=0, errors=[];
    for(const inv of pending){
      try{ await generateEntry(env, inv.id); count++; }
      catch(e){ errors.push({id:inv.id, error:e.message}); }
    }
    return json({ok:true, count, errors});
  }
  m=p.match(/^\/companies\/([^/]+)\/mark-exported$/); if(m && request.method==='POST'){
    await ensureCompany(env,user.id,m[1]);
    const result=await env.DB.prepare("UPDATE invoices SET status='exported', updated_at=? WHERE company_id=? AND status IN ('approved','accounted')").bind(now(),m[1]).run();
    return json({ok:true, changed: result.meta?.changes || 0});
  }
  m=p.match(/^\/companies\/([^/]+)\/export\.csv$/); if(m && request.method==='GET'){ await ensureCompany(env,user.id,m[1]); const rows=(await env.DB.prepare('SELECT i.*, l.account, l.description line_description, l.debit, l.credit, l.cost_center FROM invoices i LEFT JOIN accounting_entries e ON e.invoice_id=i.id LEFT JOIN accounting_entry_lines l ON l.entry_id=e.id WHERE i.company_id=? ORDER BY i.issue_date DESC').bind(m[1]).all()).results||[]; const csv=['factura;fecha;proveedor;nit;cufe;cuenta;descripcion;debito;credito;centro_costo;estado',...rows.filter(r=>r.account).map(r=>[r.invoice_number,r.issue_date,r.supplier_name,r.supplier_nit,r.cufe,r.account,r.line_description,r.debit,r.credit,r.cost_center,r.status].map(v=>`"${String(v??'').replace(/"/g,'""')}"`).join(';'))].join('\n'); return text(csv,200,'text/csv; charset=utf-8'); }
  return json({detail:'Ruta no encontrada'},404);
}catch(e){ if(e instanceof Response) return e; return json({detail:e.message||String(e)},500); }}



async function saveParsedInvoiceForCompany(env, company, parsed, sourceName='email'){
  if(nitClean(parsed.customer_nit)!==nitClean(company.nit)) throw new Error(`Factura rechazada: receptor ${parsed.customer_nit} no coincide con empresa ${company.nit}`);
  const exists=await env.DB.prepare('SELECT id FROM invoices WHERE company_id=? AND cufe=?').bind(company.id, parsed.cufe).first();
  const finalId=exists?.id || id();
  if(exists){
    await env.DB.prepare('DELETE FROM invoice_items WHERE invoice_id=?').bind(finalId).run();
    await env.DB.prepare('DELETE FROM accounting_entry_lines WHERE entry_id IN (SELECT id FROM accounting_entries WHERE invoice_id=?)').bind(finalId).run().catch(()=>{});
    await env.DB.prepare('DELETE FROM accounting_entries WHERE invoice_id=?').bind(finalId).run().catch(()=>{});
    await env.DB.prepare('UPDATE invoices SET invoice_number=?, issue_date=?, document_type=?, supplier_name=?, supplier_nit=?, customer_name=?, customer_nit=?, currency=?, subtotal=?, tax_amount=?, withholding_amount=?, payable_amount=?, status=?, raw_xml=?, updated_at=? WHERE id=?').bind(parsed.invoice_number,parsed.issue_date,parsed.document_type,parsed.supplier_name,parsed.supplier_nit,parsed.customer_name,parsed.customer_nit,parsed.currency,parsed.subtotal,parsed.tax_amount,parsed.withholding_amount,parsed.payable_amount,'received',parsed.invoice_xml,now(),finalId).run();
  }else{
    await env.DB.prepare('INSERT INTO invoices VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(finalId,company.id,parsed.invoice_number,parsed.cufe,parsed.issue_date,parsed.document_type,parsed.supplier_name,parsed.supplier_nit,parsed.customer_name,parsed.customer_nit,parsed.currency,parsed.subtotal,parsed.tax_amount,parsed.withholding_amount,parsed.payable_amount,'received',parsed.invoice_xml,now(),now()).run();
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
        const entries=await extractZipEntries(att.bytes.buffer);
        for(const entry of entries){ try{ imported.push(await saveParsedInvoiceForCompany(env, company, await parseInvoice(entry.text), entry.name)); }catch(e){ errors.push({file:entry.name,error:e.message}); } }
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
