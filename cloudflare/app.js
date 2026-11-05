import { page } from './ui.js';
import networkCheck from './check.js';
import {beginGmail,finishGmail,imapLogin,saveMailbox,syncMailbox,smtpLogin} from './mail.js';
import {automationTick,generateReply} from './automate.js';

const enc=new TextEncoder();
const random=()=>Array.from(crypto.getRandomValues(new Uint8Array(32)),x=>x.toString(16).padStart(2,'0')).join('');
const hex=a=>Array.from(new Uint8Array(a),x=>x.toString(16).padStart(2,'0')).join('');
const digest=async s=>hex(await crypto.subtle.digest('SHA-256',enc.encode(s)));
const now=()=>Math.floor(Date.now()/1000);
const validEmail=s=>typeof s==='string'&&s.length<=254&&/^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$/.test(s);
const normalize=s=>String(s||'').trim().toLowerCase();
const bad=(message,status=400)=>Object.assign(new Error(message),{status});
const safeUser=u=>({id:u.id,email:u.email,role:u.role,companyId:u.company_id});
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY'};
const json=(data,status=200,extra={})=>Response.json(data,{status,headers:{...headers,...extra}});
async function hashPassword(password,salt=random()){
 if(typeof password!=='string'||password.length<12||password.length>128)throw bad('Use a password between 12 and 128 characters.');
 const k=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);
 const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(salt),iterations:100000,hash:'SHA-256'},k,256);
 return `pbkdf2:100000:${salt}:${hex(bits)}`;
}
async function verifyPassword(password,stored){try{const parts=stored.split(':');if(parts[0]!=='pbkdf2'||parts[1]!=='100000')return false;const computed=await hashPassword(password,parts[2]);return await digest(computed)===await digest(stored)}catch{return false}}
function cookie(request){return (request.headers.get('Cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('__Host-mailagent='))?.split('=')[1]||''}
const sessionCookie=token=>`__Host-mailagent=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200`;
async function session(request,env){const token=cookie(request);if(!/^[a-f0-9]{64}$/.test(token))return null;return await env.DB.prepare('SELECT s.token_hash,s.csrf_hash,u.id,u.email,u.role,u.company_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').bind(await digest(token),now()).first()}
async function requireUser(request,env,write=false){const u=await session(request,env);if(!u)throw bad('Please sign in.',401);if(write){const csrf=request.headers.get('X-CSRF-Token')||'';if(await digest(csrf)!==u.csrf_hash)throw bad('Please refresh this page and try again.',403)}return u}
async function owner(request,env,write=false){const u=await requireUser(request,env,write);if(u.role!=='owner')throw bad('Owner access required.',403);return u}
function access(u,id){if(u.role!=='owner'&&u.company_id!==id)throw bad('Company not found.',404)}
async function body(request){const length=Number(request.headers.get('Content-Length')||0);if(length>20000)throw bad('Request too large.',413);const text=await request.text();if(text.length>20000)throw bad('Request too large.',413);try{return JSON.parse(text)}catch{throw bad('Invalid request.')}}
async function audit(env,u,action,companyId=null){await env.DB.prepare('INSERT INTO audit_events(id,company_id,user_id,action,created_at) VALUES(?,?,?,?,?)').bind(crypto.randomUUID(),companyId,u?.id||null,action,now()).run()}
async function startSession(env,user){const token=random(),csrf=random();await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,csrf_hash,expires_at) VALUES(?,?,?,?)').bind(await digest(token),user.id,await digest(csrf),now()+43200).run();return json({user:safeUser(user),csrf},200,{'Set-Cookie':sessionCookie(token)})}
async function throttle(env,request,email){const ip=request.headers.get('CF-Connecting-IP')||'unknown';const key=await digest(ip+'|'+email);let row=await env.DB.prepare('SELECT attempts,reset_at FROM login_limits WHERE key=?').bind(key).first();if(row&&row.reset_at>now()&&row.attempts>=8)throw bad('Too many attempts. Wait 15 minutes.',429);await env.DB.prepare('INSERT INTO login_limits(key,attempts,reset_at) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN reset_at<=? THEN 1 ELSE attempts+1 END,reset_at=CASE WHEN reset_at<=? THEN excluded.reset_at ELSE reset_at END').bind(key,now()+900,now(),now()).run()}
async function api(request,env,url){
 const p=url.pathname,method=request.method;
 if(!env.DB)return json({error:'Database connection is not configured. No accounts or inboxes are available.'},503);
 if(method==='GET'&&p==='/api/status'){
  const existing=await env.DB.prepare("SELECT id FROM users WHERE role='owner' LIMIT 1").first();
  return json({ownerExists:!!existing,setupAvailable:!existing&&!!env.SETUP_HASH,mailIntegrationReady:!!env.AI,gmailConfigured:!!(env.GOOGLE_CLIENT_ID&&env.GOOGLE_CLIENT_SECRET),aiConfigured:!!env.AI});
 }
 if(method==='GET'&&p==='/api/oauth/gmail/callback'){const path=await finishGmail(request,env,url);return new Response(null,{status:303,headers:{...headers,Location:path,'Set-Cookie':'__Host-mailagent-oauth=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0'}})}
 if(method==='POST'&&p==='/api/owner/test-ai'){await owner(request,env,true);const reply=await generateReply(env,{name:'Test furniture store',instructions:'We sell tables and chairs. Website https://example.com. No prices or availability may be quoted.'},{subject:'What do you sell?',body:'Hello, do you sell furniture?'});return json({ok:true,result:reply})}
 if(method==='POST'&&p==='/api/setup'){
  const b=await body(request);await throttle(env,request,'setup');
  if(!env.SETUP_HASH||await digest(String(b.token||''))!==env.SETUP_HASH)throw bad('Owner setup has not been authorized.',403);
  const email=normalize(b.email);if(email!==normalize(env.OWNER_EMAIL)||!validEmail(email))throw bad('Use the authorized owner email address.');
  const user={id:crypto.randomUUID(),email,role:'owner',company_id:null};
  const hash=await hashPassword(b.password);
  try{await env.DB.prepare("INSERT INTO users(id,email,password_hash,role,company_id,created_at) VALUES(?,?,?,'owner',NULL,?)").bind(user.id,email,hash,now()).run()}catch{throw bad('Owner setup is already complete.',409)}
  await audit(env,user,'owner_setup');return startSession(env,user);
 }
 if(method==='POST'&&p==='/api/login'){
  const b=await body(request),email=normalize(b.email);await throttle(env,request,email);
  const u=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
  const fallback='pbkdf2:100000:0000000000000000000000000000000000000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000';
  const good=await verifyPassword(b.password,u?.password_hash||fallback);if(!u||!good)throw bad('Email or password is incorrect.',401);
  await audit(env,u,'sign_in',u.company_id);return startSession(env,u);
 }
 if(method==='GET'&&p==='/api/session'){
  const u=await requireUser(request,env);const csrf=random();await env.DB.prepare('UPDATE sessions SET csrf_hash=? WHERE token_hash=?').bind(await digest(csrf),u.token_hash).run();return json({user:safeUser(u),csrf});
 }
 if(method==='POST'&&p==='/api/logout'){
  const u=await requireUser(request,env,true);await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(u.token_hash).run();return json({ok:true},200,{'Set-Cookie':'__Host-mailagent=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0'});
 }
 if(method==='POST'&&p==='/api/invite/accept'){
  const b=await body(request);await throttle(env,request,'invite');let invite=await env.DB.prepare('SELECT * FROM invitations WHERE token_hash=? AND expires_at>? AND used_at IS NULL').bind(await digest(String(b.token||'')),now()).first();
  if(!invite)throw bad('This invitation is invalid or expired.',403);
  const u={id:crypto.randomUUID(),email:invite.email,role:'company',company_id:invite.company_id},hash=await hashPassword(b.password);
  try{const result=await env.DB.batch([
   env.DB.prepare("INSERT INTO users(id,email,password_hash,role,company_id,created_at) SELECT ?,?,?,'company',?,? WHERE EXISTS(SELECT 1 FROM invitations WHERE token_hash=? AND used_at IS NULL AND expires_at>?)").bind(u.id,u.email,hash,u.company_id,now(),invite.token_hash,now()),
   env.DB.prepare('UPDATE invitations SET used_at=? WHERE token_hash=? AND used_at IS NULL').bind(now(),invite.token_hash)
  ]);if(!result[0].meta.changes)throw bad('This invitation was already used.',409)}catch{throw bad('This invitation cannot be used. Ask the owner for help.',409)}
  await audit(env,u,'invitation_accepted',u.company_id);return startSession(env,u);
 }
 if(p==='/api/companies'&&method==='GET'){
  const u=await requireUser(request,env);const r=await (u.role==='owner'?env.DB.prepare('SELECT * FROM companies ORDER BY created_at DESC'):env.DB.prepare('SELECT * FROM companies WHERE id=?').bind(u.company_id)).all();return json({companies:r.results});
 }
 if(p==='/api/companies'&&method==='POST'){
  const u=await owner(request,env,true),b=await body(request),slug=normalize(b.slug),name=String(b.name||'').trim(),email=normalize(b.email),accent=String(b.accent||'#6c56da');
  if(!/^[a-z][a-z0-9-]{1,49}$/.test(slug)||['api','login','setup','owner','invite','logout','check','favicon'].includes(slug))throw bad('Use a unique page ID of 2–50 lowercase letters, numbers or hyphens, starting with a letter.');
  if(!name||name.length>80||!validEmail(email)||!/^#[a-fA-F0-9]{6}$/.test(accent))throw bad('Enter a company name, valid client email and color.');
  const ownerManaged=email===u.email;
  if(!ownerManaged&&await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first())throw bad('This email already has an account. Use a different company login email.',409);
  const id=crypto.randomUUID(),token=random();
  try{await env.DB.batch([
   env.DB.prepare('INSERT INTO companies(id,slug,name,accent,created_at) VALUES(?,?,?,?,?)').bind(id,slug,name,accent,now()),
   ...(!ownerManaged?[env.DB.prepare('INSERT INTO invitations(token_hash,company_id,email,expires_at) VALUES(?,?,?,?)').bind(await digest(token),id,email,now()+172800)]:[])
  ])}catch{throw bad('That company page ID is already in use.',409)}
  await audit(env,u,'company_created',id);return json({id,slug,inviteUrl:ownerManaged?null:url.origin+'/invite#'+token,ownerManaged,workspaceUrl:url.origin+'/'+slug,expiresInHours:ownerManaged?null:48},201);
 }
 const match=p.match(/^\/api\/companies\/([a-f0-9-]+)(?:\/(rules|messages|mailboxes))?$/);
 if(match){
  const u=await requireUser(request,env,method!=='GET'),id=match[1];access(u,id);
  const c=await env.DB.prepare('SELECT * FROM companies WHERE id=?').bind(id).first();if(!c)throw bad('Company not found.',404);
  if(method==='GET'&&!match[2]){const health=await env.DB.prepare('SELECT last_tick,last_error FROM worker_health WHERE id=1').first();return json({company:c,worker:health})}
  if(method==='PUT'&&!match[2]){
   const b=await body(request),instructions=String(b.instructions||''),human=normalize(b.humanEmail);
   if(instructions.length>5000||human&&!validEmail(human))throw bad('Check the instructions and human email.');
   const enabled=b.autoReply===true;
   if(enabled){if(!env.AI)throw bad('The AI service is not connected.',409);if(instructions.trim().length<40||!validEmail(human))throw bad('Add company facts and a human email before enabling automation.',409);const boxes=(await env.DB.prepare('SELECT address,send_allowed FROM mailbox_accounts WHERE company_id=? AND enabled=1').bind(id).all()).results;if(!boxes.length||boxes.some(x=>!x.send_allowed))throw bad('Connect a mailbox and grant sending permission for every active mailbox first.',409);if(boxes.some(x=>normalize(x.address)===human))throw bad('Use a different human mailbox to prevent forwarding loops.',409);if(!c.auto_reply&&b.confirmAutomation!==true)throw bad('Confirm automatic sending and AI email processing before enabling it.',409)}
   await env.DB.prepare('UPDATE companies SET instructions=?,human_email=?,auto_reply=?,automation_started_at=? WHERE id=?').bind(instructions,human,enabled?1:0,enabled?(c.auto_reply?c.automation_started_at:now()):c.automation_started_at,id).run();
   if(enabled&&!c.auto_reply)await env.DB.prepare('UPDATE mailbox_accounts SET cursor=NULL WHERE company_id=?').bind(id).run();await audit(env,u,'settings_updated',id);return json({ok:true});
  }
  if(match[2]==='rules'&&method==='GET'){const r=await env.DB.prepare('SELECT id,sender,human_email,enabled FROM forwarding_rules WHERE company_id=? ORDER BY sender').bind(id).all();return json({rules:r.results})}
  if(match[2]==='rules'&&method==='POST'){
   const b=await body(request),sender=normalize(b.sender),to=normalize(b.humanEmail);if(!validEmail(sender)||!validEmail(to)||sender===to)throw bad('Enter two different valid email addresses.');
   try{await env.DB.prepare('INSERT INTO forwarding_rules(id,company_id,sender,human_email) VALUES(?,?,?,?)').bind(crypto.randomUUID(),id,sender,to).run()}catch{throw bad('A rule for this sender already exists.',409)}await audit(env,u,'forwarding_rule_created',id);return json({ok:true},201);
  }
  if(match[2]==='messages'&&method==='GET'){const r=await env.DB.prepare('SELECT id,sender,subject,body,received_at,status,reply_text,forwarded_to,last_error FROM messages WHERE company_id=? ORDER BY received_at DESC LIMIT 100').bind(id).all();return json({messages:r.results})}
  if(match[2]==='mailboxes'&&method==='POST'){
   const b=await body(request);await throttle(env,request,'mailbox:'+u.id);
   if(b.provider==='gmail'){const flow=await beginGmail(request,env,u,id,url.origin);return json({url:flow.url},200,{'Set-Cookie':flow.cookie})}
   if(b.provider!=='infomaniak'||!validEmail(normalize(b.address))||typeof b.password!=='string'||!b.password||b.password.length>512)throw bad('Enter your Infomaniak mailbox address and its mail password.');
   if(!env.MAILBOX_KEY)throw bad('Secure mailbox storage is not configured.',503);
   const address=normalize(b.address),check=await imapLogin(address,b.password);await check.close();const smtp=await smtpLogin(address,b.password);await smtp.close();
   const mailboxId=await saveMailbox(env,id,'infomaniak',address,{password:b.password});await env.DB.prepare('UPDATE mailbox_accounts SET send_allowed=1 WHERE id=?').bind(mailboxId).run();await audit(env,u,'infomaniak_connected',id);return json({ok:true,mailboxId},201);
  }
  if(match[2]==='mailboxes'&&method==='GET'){const r=await env.DB.prepare('SELECT id,provider,address,enabled,send_allowed,last_error,last_sync_at FROM mailbox_accounts WHERE company_id=?').bind(id).all();return json({mailboxes:r.results})}
 }
 const mailbox=p.match(/^\/api\/mailboxes\/([a-f0-9-]+)(?:\/(sync))?$/);
 if(mailbox){const u=await requireUser(request,env,true);const m=await env.DB.prepare('SELECT * FROM mailbox_accounts WHERE id=?').bind(mailbox[1]).first();if(!m)throw bad('Mailbox not found.',404);access(u,m.company_id);
  if(method==='DELETE'&&!mailbox[2]){await env.DB.prepare("UPDATE mailbox_accounts SET enabled=0,credentials_ciphertext='',send_allowed=0,last_error=NULL WHERE id=?").bind(m.id).run();await audit(env,u,'mailbox_disconnected',m.company_id);return json({ok:true})}
  if(method==='POST'&&mailbox[2]==='sync'){const lock=await env.DB.prepare('INSERT INTO mailbox_sync_locks(mailbox_id,expires_at) VALUES(?,?) ON CONFLICT(mailbox_id) DO UPDATE SET expires_at=excluded.expires_at WHERE expires_at<?').bind(m.id,now()+45,now()).run();if(!lock.meta.changes)throw bad('This inbox was just refreshed. Try again shortly.',429);const count=await syncMailbox(env,m);return json({ok:true,imported:count})}
 }
 const rule=p.match(/^\/api\/rules\/([a-f0-9-]+)$/);
 if(rule&&method==='DELETE'){const u=await requireUser(request,env,true),r=await env.DB.prepare('SELECT company_id FROM forwarding_rules WHERE id=?').bind(rule[1]).first();if(!r)throw bad('Rule not found.',404);access(u,r.company_id);await env.DB.prepare('DELETE FROM forwarding_rules WHERE id=? AND company_id=?').bind(rule[1],r.company_id).run();await audit(env,u,'forwarding_rule_removed',r.company_id);return json({ok:true})}
 throw bad('Not found.',404);
}
export default {
 async scheduled(event,env,ctx){ctx.waitUntil(automationTick(env));},
 async fetch(request,env,ctx){
  const url=new URL(request.url);if(url.pathname==='/check')return networkCheck.fetch(request,env,ctx);
  if(url.pathname==='/favicon.ico')return new Response(null,{status:204});
  try{
   if(request.method!=='GET'&&request.headers.get('Origin')!==url.origin)throw bad('Request origin is not allowed.',403);
   if(url.pathname.startsWith('/api/'))return await api(request,env,url);
   if(request.method!=='GET')throw bad('Method not allowed.',405);
   const nonce=random();return new Response(page(nonce),{headers:{...headers,'Content-Type':'text/html; charset=utf-8','Content-Security-Policy':`default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; style-src-attr 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`}});
  }catch(error){if(error.status)return json({error:error.message},error.status);console.error('MailAgent request failed',error.name);return json({error:'The service could not complete this request. Please try again.'},503)}
 }
};
