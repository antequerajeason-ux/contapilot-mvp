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
function removeLineBlocks(xml){ return String(xml||'').replace(/<(?:\w+:)?InvoiceLine\b[\s\S]*?<\/(?:\w+:)?InvoiceLine>/gi,'').replace(/<(?:\w+:)?CreditNoteLine\b[\s\S]*?<\/(?:\w+:)?CreditNoteLine>/gi,'').replace(/<(?:\w+:)?DebitNoteLine\b[\s\S]*?<\/(?:\w+:)?DebitNoteLine>/gi,''); }
function sumBlocks(xml, blockTag, amountTag='TaxAmount'){
  let total=0;
  const re=new RegExp(`<(?:\\w+:)?${blockTag}\\b[\\s\\S]*?<\\/(?:\\w+:)?${blockTag}>`,'gi');
  for(const m of String(xml||'').matchAll(re)) total += num(tagText(m[0], amountTag));
  return total;
}
function round2(n){ return Math.round((Number(n)||0)*100)/100; }

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
  const subtotal=round2(num(tagText(monetary,'TaxExclusiveAmount') || tagText(monetary,'LineExtensionAmount')));
  const payable=round2(num(tagText(monetary,'PayableAmount') || tagText(monetary,'TaxInclusiveAmount')) || subtotal);

  // IMPORTANTE: DIAN puede traer TaxTotal a nivel factura y también dentro de cada línea.
  // Para no duplicar IVA, quitamos InvoiceLine/CreditNoteLine/DebitNoteLine antes de sumar impuestos globales.
  const headerXml=removeLineBlocks(xml);
  let tax=round2(sumBlocks(headerXml,'TaxTotal','TaxAmount'));
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
  return {invoice_xml:xml, invoice_number:invoiceNumber, cufe, issue_date:issueDate, document_type:root==='Invoice'?'Factura compra':root==='CreditNote'?'Nota crédito':'Nota débito', supplier_name:supplier.name, supplier_nit:supplier.nit, customer_name:customer.name, customer_nit:customer.nit, currency, subtotal, tax_amount:tax, withholding_amount:withholding, payable_amount:payable, items};
}
async function auth(env, request){ const h=request.headers.get('authorization')||''; if(!h.toLowerCase().startsWith('bearer ')) throw new Response(JSON.stringify({detail:'Falta token Authorization: Bearer'}),{status:401}); const token=h.split(' ')[1]; const row=await env.DB.prepare('SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=?').bind(token).first(); if(!row) throw new Response(JSON.stringify({detail:'Sesión inválida'}),{status:401}); return row; }
async function ensureCompany(env,userId,companyId){ const c=await env.DB.prepare('SELECT * FROM companies WHERE id=? AND owner_user_id=?').bind(companyId,userId).first(); if(!c) throw new Response(JSON.stringify({detail:'Empresa no encontrada'}),{status:404}); return c; }
async function getSettings(env, companyId){ const s=await env.DB.prepare('SELECT * FROM accounting_settings WHERE company_id=?').bind(companyId).first(); return normalizeSettings(s||{}); }
function normalizeSettings(s){
  // Normalización basada en plan de cuentas DISTRIBUCIONES TORRES GARCIA SAS / Siigo.
  // Evita usar cuentas padre y prefiere cuentas transaccionales.
  const out={...s};
  if(!out.vat_account || out.vat_account==='240805' || out.vat_account==='240810') out.vat_account='24081001';
  if(!out.vat_description || out.vat_description==='IVA descontable') out.vat_description='Iva descontable por compras 19%';
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

async function generateEntry(env, invoiceId){
  const inv=await env.DB.prepare('SELECT * FROM invoices WHERE id=?').bind(invoiceId).first();
  if(!inv) throw new Error('Factura no encontrada');
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
      inv.withholding_amount=reparsed.withholding_amount;
      inv.payable_amount=reparsed.payable_amount;
      await env.DB.prepare('UPDATE invoices SET invoice_number=?, issue_date=?, document_type=?, supplier_name=?, supplier_nit=?, customer_name=?, customer_nit=?, currency=?, subtotal=?, tax_amount=?, withholding_amount=?, payable_amount=?, updated_at=? WHERE id=?')
        .bind(inv.invoice_number,inv.issue_date,inv.document_type,inv.supplier_name,inv.supplier_nit,inv.customer_name,inv.customer_nit,inv.currency,inv.subtotal,inv.tax_amount,inv.withholding_amount,inv.payable_amount,now(),invoiceId).run();
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
    await env.DB.prepare("UPDATE accounting_entries SET status='suggested', confidence=?, created_at=?, approved_at=NULL WHERE id=?").bind(.88, now(), entryId).run();
  } else {
    await env.DB.prepare('INSERT INTO accounting_entries VALUES (?,?,?,?,?,?)').bind(entryId, invoiceId, 'suggested', .88, now(), null).run();
  }

  const linesToInsert=[];
  const push=(account,description,debit,credit,cost='')=>{
    linesToInsert.push({account:normalizeAccountCode(account),description,debit:round2(debit||0),credit:round2(credit||0),cost});
  };

  const expenseAccount=inferPurchaseAccount(inv, rule?.account || settings.default_expense_account);
  const expenseDescription=(expenseAccount==='14350101')?'Mercancías no fabricadas':(rule?.description || settings.default_expense_description);
  push(expenseAccount, expenseDescription, inv.subtotal, 0, rule?.cost_center || settings.default_cost_center);
  if(inv.tax_amount) push(settings.vat_account, settings.vat_description, inv.tax_amount, 0, '');
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
  const lines=(await env.DB.prepare('SELECT * FROM accounting_entry_lines WHERE entry_id=?').bind(entryId).all()).results||[];
  entry=await env.DB.prepare('SELECT * FROM accounting_entries WHERE id=?').bind(entryId).first();
  return {entry,lines};
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
  const raw=String(invoiceNumber||'').trim();
  const m=raw.match(/^([A-Za-z\-]*)(\d+)$/);
  if(m) return {prefix:m[1]||'', number:m[2]};
  const digits=(raw.match(/\d+/g)||[]).join('');
  const prefix=raw.replace(/\d/g,'').slice(0,10);
  return {prefix, number:digits||raw};
}
async function siigoGetPurchaseConfig(env){
  const cfg={};
  if(env.SIIGO_PURCHASE_DOCUMENT_ID) cfg.document_id=Number(env.SIIGO_PURCHASE_DOCUMENT_ID);
  if(env.SIIGO_PAYMENT_TYPE_ID) cfg.payment_type_id=Number(env.SIIGO_PAYMENT_TYPE_ID);
  if(env.SIIGO_IVA_19_TAX_ID) cfg.iva_19_tax_id=Number(env.SIIGO_IVA_19_TAX_ID);
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
  if(!cfg.iva_19_tax_id){
    const taxes=await siigoRequest(env,'/taxes');
    const iva=Array.isArray(taxes)?taxes.find(t=>t.active && String(t.type).toUpperCase()==='IVA' && Number(t.percentage)===19):null;
    if(iva) cfg.iva_19_tax_id=iva.id;
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
async function siigoEnsureSupplier(env, invoice){
  const tercero=partyDetailsFromXml(invoice.raw_xml||'', 'AccountingSupplierParty');
  const nit=nitClean(tercero.nit || invoice.supplier_nit);
  if(!nit) throw new Error('La factura no tiene NIT de proveedor para crear/usar proveedor en Siigo');
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
  try{
    await siigoRequest(env,'/customers',{method:'POST',body:JSON.stringify(payload)});
    return {identification:nit, branch_office:0, created:true};
  }catch(e){
    const msg=String(e.message||'');
    // Si ya existe, seguimos usando identificación + sucursal 0.
    if(msg.toLowerCase().includes('exist') || msg.toLowerCase().includes('ya') || msg.toLowerCase().includes('identification')){
      return {identification:nit, branch_office:0, created:false, note:'Proveedor ya existía o Siigo no permitió crearlo; se usará identificación existente'};
    }
    // No bloqueamos inmediatamente: en muchas cuentas el proveedor ya existe aunque la creación responda distinto.
    return {identification:nit, branch_office:0, created:false, warning:msg};
  }
}
async function buildSiigoPurchasePayload(env, invoice){
  const cfg=await siigoGetPurchaseConfig(env);
  const supplier=await siigoEnsureSupplier(env, invoice);
  const pn=invoicePrefixNumber(invoice.invoice_number);
  const settings=await getSettings(env, invoice.company_id);
  const items=(await env.DB.prepare('SELECT * FROM invoice_items WHERE invoice_id=?').bind(invoice.id).all()).results||[];
  const entry=await env.DB.prepare('SELECT * FROM accounting_entries WHERE invoice_id=?').bind(invoice.id).first();
  const lines=entry?(await env.DB.prepare('SELECT * FROM accounting_entry_lines WHERE entry_id=?').bind(entry.id).all()).results||[]:[];
  const expenseLine=lines.find(l=>Number(l.debit)>0 && !String(l.account).startsWith('2408')) || {account:settings.default_expense_account, description:settings.default_expense_description};
  const description=(items[0]?.description || expenseLine.description || `Factura ${invoice.invoice_number}`).slice(0,250);
  const item={type:'Account', code:normalizeAccountCode(expenseLine.account||settings.default_expense_account), description, quantity:1, price:round2(invoice.subtotal||0)};
  if(Number(invoice.tax_amount||0)>0 && cfg.iva_19_tax_id) item.taxes=[{id:cfg.iva_19_tax_id}];
  const payload={
    document:{id:cfg.document_id},
    date:invoice.issue_date || now().slice(0,10),
    supplier:{identification:supplier.identification, branch_office:supplier.branch_office||0},
    provider_invoice:{prefix:pn.prefix||'', number:String(pn.number||invoice.invoice_number||'').slice(0,20)},
    tax_included:false,
    observations:`Creado desde ContaPilot. Factura ${invoice.invoice_number||''}. CUFE ${(invoice.cufe||'').slice(0,64)}`,
    items:[item],
    payments:[{id:cfg.payment_type_id, value:round2(invoice.payable_amount||0), due_date:invoice.issue_date || now().slice(0,10)}]
  };
  return {payload,cfg,supplier};
}

async function handleApi(request, env){ const url=new URL(request.url); const p=url.pathname.replace(/^\/api/,'') || '/'; try{
  if(request.method==='OPTIONS') return new Response(null,{status:204});
  if(p==='/health') return json({ok:true, service:'contapilot-cloudflare', time:now()});
  if(p==='/auth/register' && request.method==='POST'){ const d=await request.json(); const userId=id(); const token=id()+id(); await env.DB.prepare('INSERT INTO users VALUES (?,?,?,?,?)').bind(userId,d.name||'Contador Demo',String(d.email||'').toLowerCase(),await hashPassword(d.password||''),now()).run(); await env.DB.prepare('INSERT INTO sessions VALUES (?,?,?)').bind(token,userId,now()).run(); return json({token,user:{id:userId,name:d.name||'Contador Demo',email:String(d.email||'').toLowerCase()}}); }
  if(p==='/auth/login' && request.method==='POST'){ const d=await request.json(); const u=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(String(d.email||'').toLowerCase()).first(); if(!u || !(await verifyPassword(d.password||'', u.password_hash))) return json({detail:'Correo o contraseña inválidos'},401); const token=id()+id(); await env.DB.prepare('INSERT INTO sessions VALUES (?,?,?)').bind(token,u.id,now()).run(); return json({token,user:{id:u.id,name:u.name,email:u.email}}); }
  const user=await auth(env,request);
  if(p==='/siigo/test' && request.method==='POST'){
    const authResult=await siigoAuth(env);
    return json({ok:true, message:'Conexión con Siigo correcta', expires_in:authResult.expires_in, token_type:authResult.token_type, scope:authResult.scope});
  }
  if(p==='/siigo/catalogs' && request.method==='GET'){
    const result={ok:true,catalogs:{}};
    const docTypes={};
    for(const type of ['FC','FV','DS','NC','RC']){
      try{ docTypes[type]=await siigoRequest(env,`/document-types?type=${encodeURIComponent(type)}`); }
      catch(e){ docTypes[type]={error:e.message}; }
    }
    result.catalogs.document_types=docTypes;
    try{ result.catalogs.taxes=await siigoRequest(env,'/taxes'); }catch(e){ result.catalogs.taxes_error=e.message; }
    const paymentTypes={};
    for(const type of ['FC','FV','DS','NC','RC']){
      try{ paymentTypes[type]=await siigoRequest(env,`/payment-types?document_type=${encodeURIComponent(type)}`); }
      catch(e){ paymentTypes[type]={error:e.message}; }
    }
    result.catalogs.payment_types=paymentTypes;
    return json(result);
  }
  { const mm=p.match(/^\/companies\/([^/]+)\/siigo-upload-selected$/); if(mm && request.method==='POST'){
    await ensureCompany(env,user.id,mm[1]);
    const body=await request.json().catch(()=>({}));
    const invoiceIds=Array.isArray(body.invoice_ids)?body.invoice_ids.map(String).filter(Boolean):[];
    if(!invoiceIds.length) return json({ok:false,count:0,errors:[{error:'No seleccionaste facturas para subir a Siigo'}]},400);
    const uploaded=[], errors=[];
    for(const invoiceId of invoiceIds){
      try{
        let inv=await env.DB.prepare('SELECT * FROM invoices WHERE id=? AND company_id=?').bind(invoiceId,mm[1]).first();
        if(!inv) throw new Error('La factura no pertenece a la empresa activa');
        if(inv.status==='exported') throw new Error('La factura ya está marcada como exportada/subida');
        await generateEntry(env, invoiceId);
        inv=await env.DB.prepare('SELECT * FROM invoices WHERE id=? AND company_id=?').bind(invoiceId,mm[1]).first();
        const built=await buildSiigoPurchasePayload(env, inv);
        const result=await siigoRequest(env,'/purchases',{method:'POST',body:JSON.stringify(built.payload)});
        await env.DB.prepare("UPDATE invoices SET status='exported', updated_at=? WHERE id=?").bind(now(),invoiceId).run();
        uploaded.push({invoice_id:invoiceId, invoice_number:inv.invoice_number, siigo:result, supplier:built.supplier});
      }catch(e){
        let invErr=null; try{ invErr=await env.DB.prepare('SELECT invoice_number, supplier_name, supplier_nit FROM invoices WHERE id=?').bind(invoiceId).first(); }catch(_){ }
        errors.push({id:invoiceId, invoice_number:invErr?.invoice_number||'', supplier:invErr?.supplier_name||'', nit:invErr?.supplier_nit||'', error:e.message});
      }
    }
    return json({ok:uploaded.length>0, count:uploaded.length, uploaded, errors});
  }}
  if(p==='/companies' && request.method==='GET'){ const rows=(await env.DB.prepare('SELECT * FROM companies WHERE owner_user_id=? ORDER BY created_at DESC').bind(user.id).all()).results||[]; return json(rows); }
  if(p==='/companies' && request.method==='POST'){ const d=await request.json(); const companyId=id(); await env.DB.prepare('INSERT INTO companies VALUES (?,?,?,?,?)').bind(companyId,user.id,d.name,nitClean(d.nit),now()).run(); await env.DB.prepare('INSERT INTO accounting_settings (company_id) VALUES (?)').bind(companyId).run(); for(const r of [['supplier','CLARO','51353501','Servicios públicos - Teléfono','Administración',10],['supplier','CLASSIC JEANS','51952501','Elementos de aseo y cafetería','Administración',35],['default','*','52959505','Gastos diversos POS','Administración',999]]) await env.DB.prepare('INSERT INTO accounting_rules VALUES (?,?,?,?,?,?,?,?,?,?)').bind(id(),companyId,r[0],r[1],r[2],r[3],r[4],r[5],1,now()).run(); return json(await env.DB.prepare('SELECT * FROM companies WHERE id=?').bind(companyId).first()); }
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
    return json(await env.DB.prepare('SELECT * FROM companies WHERE id=?').bind(m[1]).first());
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
    await env.DB.prepare('DELETE FROM companies WHERE id=? AND owner_user_id=?').bind(m[1],user.id).run();
    return json({ok:true, deleted:m[1]});
  }
  m=p.match(/^\/companies\/([^/]+)\/settings$/); if(m && request.method==='GET'){ await ensureCompany(env,user.id,m[1]); return json(await getSettings(env,m[1])); }
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
          if(!entries.length){
            const detail=zipStatsMessage(entries.stats);
            errors.push({file:file.name,error: detail ? `El ZIP no contiene XML/HTML/TXT procesable. ${detail}. Si solo contiene PDF, descarga desde DIAN el XML de las facturas.` : 'El ZIP no contiene XML/HTML/TXT procesable'});
            continue;
          }
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
        const inv=await env.DB.prepare('SELECT id,status FROM invoices WHERE id=? AND company_id=?').bind(invoiceId,m[1]).first();
        if(!inv) throw new Error('La factura no pertenece a la empresa activa');
        if(inv.status==='exported') throw new Error('La factura ya está exportada y no se recausa');
        await generateEntry(env, invoiceId);
        count++;
      }catch(e){ errors.push({id:invoiceId, error:e.message}); }
    }
    return json({ok:!errors.length || count>0, count, errors});
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
