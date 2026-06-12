"use strict";
/* Katha Catalogue & Rights — app logic. Local-first: IndexedDB, no server. */

/* ---------- auth: multi-user, salted hashes, lockout, roles ---------- */
const USERS_KEY="katha_users", SESSION_KEY="katha_sess", LOCK_KEY="katha_lock";
let currentUser=null;

async function sha256(str){
  const buf=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}
function randSalt(){const a=new Uint8Array(12);crypto.getRandomValues(a);return Array.from(a).map(b=>b.toString(16).padStart(2,"0")).join("")}
function getUsers(){try{return JSON.parse(localStorage.getItem(USERS_KEY))||[]}catch(_){return[]}}
function setUsers(u){localStorage.setItem(USERS_KEY,JSON.stringify(u))}
function getLock(){try{return JSON.parse(localStorage.getItem(LOCK_KEY))||{fails:0,until:0}}catch(_){return{fails:0,until:0}}}
function setLock(l){localStorage.setItem(LOCK_KEY,JSON.stringify(l))}

function sessionUser(){
  try{
    const raw=sessionStorage.getItem(SESSION_KEY)||localStorage.getItem(SESSION_KEY);
    if(!raw)return null;
    const s=JSON.parse(raw);
    if(Date.now()>s.exp)return null;
    const u=getUsers().find(x=>x.id===s.uid&&!x.disabled);
    return u?{id:u.id,name:u.name,username:u.username,role:u.role}:null;
  }catch(_){return null}
}
async function doSetup(){
  const name=$("suName").value.trim(),user=$("suUser").value.trim().toLowerCase();
  const pw=$("suPw").value,pw2=$("suPw2").value,err=$("serr");
  const fail=m=>{err.textContent=m;err.classList.add("on")};
  if(!name||!user)return fail("Name and username are required");
  if(/\s/.test(user))return fail("Username cannot contain spaces");
  if(pw.length<8)return fail("Password must be at least 8 characters");
  if(pw!==pw2)return fail("Passwords don't match");
  const salt=randSalt();
  const u={id:uid(),name,username:user,role:"Admin",salt,hash:await sha256(salt+pw),createdAt:Date.now()};
  setUsers([u]);
  err.classList.remove("on");
  startSession(u,true);
}
async function doLogin(){
  const lock=getLock();
  const err=$("lerr"),fail=m=>{err.textContent=m;err.classList.add("on")};
  if(Date.now()<lock.until)return fail("Too many failed attempts — locked for "+Math.ceil((lock.until-Date.now())/60000)+" more minute(s)");
  const uname=$("loginUser").value.trim().toLowerCase(),pw=$("loginPw").value;
  if(!uname||!pw)return fail("Enter username and password");
  const u=getUsers().find(x=>x.username===uname&&!x.disabled);
  const ok=u&&(await sha256(u.salt+pw))===u.hash;
  if(!ok){
    const l=getLock();l.fails=(l.fails||0)+1;
    if(l.fails>=5){l.until=Date.now()+5*60*1000;l.fails=0;setLock(l);return fail("Too many failed attempts — sign-in locked for 5 minutes")}
    setLock(l);return fail("Incorrect username or password ("+(5-l.fails)+" attempts left)");
  }
  setLock({fails:0,until:0});err.classList.remove("on");
  u.lastLogin=Date.now();const us=getUsers();const i=us.findIndex(x=>x.id===u.id);us[i]=u;setUsers(us);
  startSession(u,$("remDev").checked);
}
function startSession(u,remember){
  const dur=remember?(30*24*60*60*1000):(8*60*60*1000);
  const s=JSON.stringify({uid:u.id,exp:Date.now()+dur});
  if(remember)localStorage.setItem(SESSION_KEY,s);else sessionStorage.setItem(SESSION_KEY,s);
  currentUser={id:u.id,name:u.name,username:u.username,role:u.role};
  $("loginScreen").classList.add("gone");
  applyRole();initApp();
}
function applyRole(){
  document.body.classList.toggle("role-viewer",currentUser.role==="Viewer");
  const w=$("whoami");
  if(w)w.innerHTML=`<b style="color:var(--ink)">${esc(currentUser.name)}</b><br><span class="tag ${currentUser.role==="Admin"?"teal":currentUser.role==="Editor"?"green":"gray"}" style="margin-top:3px;display:inline-block">${currentUser.role}</span>`;
  const tp=$("teamPanel");
  if(tp)tp.style.display=currentUser.role==="Admin"?"":"none";
  if(currentUser.role==="Admin")renderUsers();
}
function canEdit(){
  if(currentUser&&currentUser.role!=="Viewer")return true;
  toast("Your account is view-only — ask an admin for Editor access");return false;
}
function togglePw(){
  const i=$("loginPw");
  i.type=i.type==="password"?"text":"password";
  $("eyeBtn").textContent=i.type==="password"?"👁":"🙈";
}
async function changePassword(){
  const cur=$("cpCur").value,nw=$("cpNew").value,cf=$("cpConf").value;
  if(!cur||!nw)return toast("Fill in current and new password");
  if(nw!==cf)return toast("New passwords don't match");
  if(nw.length<8)return toast("New password must be at least 8 characters");
  const us=getUsers(),i=us.findIndex(x=>x.id===currentUser.id);
  if(i<0)return toast("Account not found");
  if((await sha256(us[i].salt+cur))!==us[i].hash)return toast("Current password is incorrect");
  us[i].salt=randSalt();us[i].hash=await sha256(us[i].salt+nw);setUsers(us);
  $("cpCur").value="";$("cpNew").value="";$("cpConf").value="";
  toast("Password updated");
}
function signOut(){
  sessionStorage.removeItem(SESSION_KEY);localStorage.removeItem(SESSION_KEY);
  location.reload();
}

/* ---------- admin: team management ---------- */
function renderUsers(){
  const us=getUsers();
  $("userList").innerHTML=us.map(u=>`
    <div class="user-row">
      <span class="uname">${esc(u.name)}${u.disabled?' <span class="tag red">disabled</span>':""}</span>
      <span style="color:var(--ink-3);font-size:12.5px">@${esc(u.username)}</span>
      <select onchange="setRole('${u.id}',this.value)" ${u.id===currentUser.id?"disabled":""}>
        ${["Admin","Editor","Viewer"].map(r=>`<option ${u.role===r?"selected":""}>${r}</option>`).join("")}
      </select>
      <span style="flex:1"></span>
      <button class="btn sm" onclick="resetUserPw('${u.id}')">Reset password</button>
      ${u.id===currentUser.id?'<span class="tag teal">you</span>':`<button class="btn sm ${u.disabled?"":"warn"}" onclick="toggleUser('${u.id}')">${u.disabled?"Re-enable":"Disable"}</button>`}
    </div>`).join("");
}
async function addUser(){
  if(currentUser.role!=="Admin")return;
  const name=$("nuName").value.trim(),uname=$("nuUser").value.trim().toLowerCase(),role=$("nuRole").value,pw=$("nuPw").value;
  if(!name||!uname)return toast("Name and username are required");
  if(/\s/.test(uname))return toast("Username cannot contain spaces");
  if(pw.length<8)return toast("Temporary password must be at least 8 characters");
  if(getUsers().some(u=>u.username===uname))return toast("That username is already taken");
  const salt=randSalt();
  const us=getUsers();
  us.push({id:uid(),name,username:uname,role,salt,hash:await sha256(salt+pw),createdAt:Date.now()});
  setUsers(us);
  $("nuName").value="";$("nuUser").value="";$("nuPw").value="";
  logAct("Team",`Added ${name} (@${uname}) as ${role}`);persist();
  renderUsers();toast(`Added ${name} — share their username and temporary password with them`);
}
async function resetUserPw(id){
  if(currentUser.role!=="Admin")return;
  const us=getUsers(),i=us.findIndex(x=>x.id===id);
  if(i<0)return;
  const pw=prompt(`New temporary password for ${us[i].name} (min 8 characters):`);
  if(pw===null)return;
  if(pw.length<8)return toast("Password must be at least 8 characters");
  us[i].salt=randSalt();us[i].hash=await sha256(us[i].salt+pw);setUsers(us);
  logAct("Team",`Reset password for ${us[i].name}`);persist();
  toast(`Password reset for ${us[i].name} — share the new one with them`);
}
function setRole(id,role){
  if(currentUser.role!=="Admin")return;
  const us=getUsers(),i=us.findIndex(x=>x.id===id);
  if(i<0)return;
  if(us[i].role==="Admin"&&role!=="Admin"&&us.filter(u=>u.role==="Admin"&&!u.disabled).length<=1){renderUsers();return toast("There must always be at least one active admin")}
  us[i].role=role;setUsers(us);
  logAct("Team",`${us[i].name} is now ${role}`);persist();
  renderUsers();toast(`${us[i].name} is now ${role}`);
}
function toggleUser(id){
  if(currentUser.role!=="Admin")return;
  const us=getUsers(),i=us.findIndex(x=>x.id===id);
  if(i<0)return;
  if(!us[i].disabled&&us[i].role==="Admin"&&us.filter(u=>u.role==="Admin"&&!u.disabled).length<=1)return toast("There must always be at least one active admin");
  us[i].disabled=!us[i].disabled;setUsers(us);
  logAct("Team",`${us[i].disabled?"Disabled":"Re-enabled"} ${us[i].name}`);persist();
  renderUsers();toast(`${us[i].name} ${us[i].disabled?"disabled":"re-enabled"}`);
}

const LANGS=["English","Hindi","Kannada","Tamil","Telugu","Marathi","Urdu","Bangla","Gujarati","Assamese","Other"];
const LCODE={English:"EN",Hindi:"HI",Kannada:"KN",Tamil:"TA",Telugu:"TE",Marathi:"MR",Urdu:"UR",Bangla:"BN",Gujarati:"GU",Assamese:"AS",Other:"XX"};
const CCODE={"Children":"CH","Young Adult":"YA","Adult":"AD"};
const FCODE={"Print":"PR","Digital print":"DP","Ebook":"EB","Audio":"AU"};

let db={meta:{seq:0,updatedAt:null},titles:[],activity:[]};
let editingId=null, genLayout="detail";

/* ---------- storage (IndexedDB, in-memory fallback) ---------- */
let idb=null;
function idbOpen(){return new Promise(res=>{try{
  const rq=indexedDB.open("katha-cat",1);
  rq.onupgradeneeded=e=>e.target.result.createObjectStore("kv");
  rq.onsuccess=e=>{idb=e.target.result;res(true)};
  rq.onerror=()=>res(false);
}catch(_){res(false)}})}
function load(){return new Promise(res=>{
  if(!idb)return res();
  const tx=idb.transaction("kv").objectStore("kv").get("db");
  tx.onsuccess=()=>{if(tx.result)db=tx.result;res()};
  tx.onerror=()=>res();
})}
let saveT=null;
function persist(){
  db.meta.updatedAt=new Date().toISOString();
  if(!idb)return;
  clearTimeout(saveT);
  saveT=setTimeout(()=>{idb.transaction("kv","readwrite").objectStore("kv").put(db,"db")},250);
}
function logAct(action,detail){const who=currentUser?(" — "+currentUser.name):"";db.activity.unshift({ts:Date.now(),action,detail:detail+who});db.activity=db.activity.slice(0,60)}

/* ---------- helpers ---------- */
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function toast(m){const t=$("toast");t.textContent=m;t.classList.add("on");setTimeout(()=>t.classList.remove("on"),2600)}
function uid(){return "t"+Date.now().toString(36)+Math.random().toString(36).slice(2,7)}
function fmtDate(d){if(!d)return"";const x=new Date(d);return isNaN(x)?"":x.toLocaleDateString("en-IN",{day:"numeric",month:"short",year:"numeric"})}
function monthsTo(dateStr){if(!dateStr)return null;return (new Date(dateStr)-Date.now())/(1000*60*60*24*30.44)}
function normStatus(s){s=String(s||"").toLowerCase();if(/reprint/.test(s))return"Reprint Planned";if(/out/.test(s))return"Out of Print";if(/in\s*stock|in\s*print|avail/.test(s))return"In Print";return"In Print"}
function makeSKU(t){
  const L=LCODE[t.language]||"XX",C=CCODE[t.category]||"CH",A=String(t.age||"6+").replace(/\D/g,"").padStart(2,"0"),F=FCODE[t.format]||"PR";
  db.meta.seq=(db.meta.seq||0)+1;
  return `KTH-${L}-${C}-${A}-${F}-${String(db.meta.seq).padStart(4,"0")}-${t.yearPub||new Date().getFullYear()}`;
}
function rightsState(t){
  const r=t.rights||{};
  if(r.cc&&/NC/.test(r.cc))return{tag:"red",label:"CC — no commercial"};
  if(r.cc==="Unknown — needs checking")return{tag:"amber",label:"CC — verify"};
  if(r.cc)return{tag:"teal",label:r.cc};
  if(!r.holder&&!r.type)return{tag:"gray",label:"No rights data"};
  const m=monthsTo(r.expiry);
  if(m!==null&&m<0)return{tag:"red",label:"Expired"};
  if(m!==null&&m<=12)return{tag:"amber",label:"Expiring "+fmtDate(r.expiry)};
  return{tag:"green",label:"Active"};
}

/* ---------- navigation ---------- */
function go(v){
  document.querySelectorAll(".view").forEach(x=>x.classList.toggle("on",x.id==="v-"+v));
  document.querySelectorAll("#nav button,#mnav button").forEach(b=>b.classList.toggle("on",b.dataset.v===v));
  if(v==="dash")renderDash();if(v==="cat")renderCat();if(v==="rights")renderRights();if(v==="gen")renderGen();
}
document.querySelectorAll("#nav button,#mnav button").forEach(b=>b.onclick=()=>go(b.dataset.v));

/* ---------- dashboard ---------- */
function renderDash(){
  const T=db.titles, langs=new Set(T.map(t=>t.language).filter(Boolean));
  const inPrint=T.filter(t=>t.status==="In Print").length;
  const noBlurb=T.filter(t=>!t.blurbShort).length;
  const exp=T.filter(t=>{const m=monthsTo(t.rights?.expiry);return m!==null&&m<=12});
  const cc=T.filter(t=>t.rights?.cc&&/NC|Unknown/.test(t.rights.cc));
  const noRights=T.filter(t=>!(t.rights&&(t.rights.holder||t.rights.type))).length;
  $("dashStats").innerHTML=[
    [T.length,"Titles"],[langs.size,"Languages"],[inPrint,"In print"],
    [exp.length,"Rights expiring ≤12 mo"],[noBlurb,"Missing blurbs"]
  ].map(([n,l])=>`<div class="stat"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");
  $("dashSub").textContent=db.meta.updatedAt?("Last change "+fmtDate(db.meta.updatedAt)):"Your catalogue at a glance";

  let A="";
  exp.slice(0,6).forEach(t=>{const m=monthsTo(t.rights.expiry);
    A+=`<div class="alert-row"><span class="tag ${m<0?"red":"amber"}">${m<0?"Expired":"Rights"}</span><span><b>${esc(t.title)}</b> — rights ${m<0?"expired":"expire"} ${fmtDate(t.rights.expiry)}. <a href="#" onclick="openTitle('${t.id}','rights');return false">Review</a></span></div>`});
  cc.slice(0,5).forEach(t=>{A+=`<div class="alert-row"><span class="tag red">Licence</span><span><b>${esc(t.title)}</b> — ${esc(t.rights.cc)}. Verify before commercial sale. <a href="#" onclick="openTitle('${t.id}','rights');return false">Open</a></span></div>`});
  if(noRights)A+=`<div class="alert-row"><span class="tag gray">Rights</span><span>${noRights} titles have no rights data yet. <a href="#" onclick="go('rights');$('rFilter').value='missing';renderRights();return false">See list</a></span></div>`;
  if(noBlurb)A+=`<div class="alert-row"><span class="tag amber">Content</span><span>${noBlurb} titles are missing a short blurb — they will appear in generated catalogues without descriptions.</span></div>`;
  $("dashAlerts").innerHTML=A||`<div class="empty" style="padding:18px">Nothing needs attention. Well kept.</div>`;

  $("dashActivity").innerHTML=db.activity.slice(0,8).map(a=>
    `<div class="alert-row"><span class="tag teal">${esc(a.action)}</span><span>${esc(a.detail)} <span style="color:var(--ink-3)">· ${fmtDate(a.ts)}</span></span></div>`
  ).join("")||`<div class="empty" style="padding:18px">No activity yet. Import your Excel files from Data &amp; backup, or load sample titles.</div>`;
}

/* ---------- catalogue list ---------- */
function fillSelect(sel,opts,keep){const cur=sel.value;sel.innerHTML=keep+opts.map(o=>`<option>${esc(o)}</option>`).join("");sel.value=cur}
function refreshFilters(){
  const langs=[...new Set(db.titles.map(t=>t.language).filter(Boolean))].sort();
  const cats=[...new Set(db.titles.map(t=>t.category).filter(Boolean))].sort();
  fillSelect($("fLang"),langs,'<option value="">All languages</option>');
  fillSelect($("fCatg"),cats,'<option value="">All categories</option>');
  fillSelect($("gLang"),langs,'<option value="">All</option>');
  fillSelect($("gCatg"),cats,'<option value="">All</option>');
}
function renderCat(){
  refreshFilters();
  const q=($("q").value||"").toLowerCase(),L=$("fLang").value,C=$("fCatg").value,S=$("fStat").value;
  const rows=db.titles.filter(t=>
    (!L||t.language===L)&&(!C||t.category===C)&&(!S||t.status===S)&&
    (!q||[t.title,t.englishTitle,t.author,t.illustrator,t.isbn].join(" ").toLowerCase().includes(q))
  ).sort((a,b)=>String(a.title).localeCompare(b.title));
  $("catCount").textContent=rows.length+" of "+db.titles.length+" titles";
  $("catBody").innerHTML=rows.map(t=>{const rs=rightsState(t);return `
    <tr class="rowlink" onclick="openTitle('${t.id}')">
      <td><div style="display:flex;gap:10px;align-items:flex-start">${coverSrc(t)?`<img src="${esc(coverSrc(t))}" style="width:30px;height:40px;object-fit:cover;border-radius:4px;flex-shrink:0" loading="lazy">`:""}<div><div class="t-title">${esc(t.title)}</div><div class="t-sub">${esc(t.englishTitle&&t.englishTitle!==t.title?t.englishTitle:"")}${t.isbn?" · "+esc(t.isbn):""}</div></div></div></td>
      <td>${esc(t.language||"")}</td><td>${esc(t.category||"")}${t.age?" · "+esc(t.age):""}</td>
      <td><div class="t-sub" style="font-size:13px;color:var(--ink-2)">${esc(t.author||"")}${t.illustrator?"<br>Illus: "+esc(t.illustrator):""}</div></td>
      <td>${t.mrp?"₹"+t.mrp:""}</td>
      <td><span class="tag ${t.status==="In Print"?"green":t.status==="Out of Print"?"red":"amber"}">${esc(t.status||"")}</span></td>
      <td><span class="tag ${rs.tag}">${esc(rs.label)}</span></td>
    </tr>`}).join("")||`<tr><td colspan="7"><div class="empty"><div class="big">No titles yet</div>Import your Excel files from Data &amp; backup, or add a title.</div></td></tr>`;
}

/* ---------- rights view ---------- */
function renderRights(){
  const T=db.titles;
  const exp=T.filter(t=>{const m=monthsTo(t.rights?.expiry);return m!==null&&m<=12&&m>=0}).length;
  const dead=T.filter(t=>{const m=monthsTo(t.rights?.expiry);return m!==null&&m<0}).length;
  const cc=T.filter(t=>t.rights?.cc).length;
  const none=T.filter(t=>!(t.rights&&(t.rights.holder||t.rights.type))).length;
  $("rStats").innerHTML=[[exp,"Expiring ≤12 mo"],[dead,"Expired"],[cc,"CC / Wikimedia"],[none,"No rights data"]]
    .map(([n,l])=>`<div class="stat"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");
  const f=$("rFilter").value;
  const rows=T.filter(t=>{
    const r=t.rights||{},m=monthsTo(r.expiry);
    if(f==="expiring")return m!==null&&m<=12&&m>=0;
    if(f==="expired")return m!==null&&m<0;
    if(f==="cc")return!!r.cc||/wikimedia/i.test(r.holderIl||"")||/wikimedia/i.test(t.illustrator||"");
    if(f==="missing")return!(r.holder||r.type);
    return true;
  }).sort((a,b)=>{const ma=monthsTo(a.rights?.expiry)??9e9,mb=monthsTo(b.rights?.expiry)??9e9;return ma-mb});
  $("rBody").innerHTML=rows.map(t=>{const r=t.rights||{},rs=rightsState(t);return `
    <tr class="rowlink" onclick="openTitle('${t.id}','rights')">
      <td><div class="t-title">${esc(t.title)}</div><div class="t-sub">${esc(t.language||"")}</div></td>
      <td>${esc(r.holder||"—")}${r.holderIl?`<div class="t-sub">Illus: ${esc(r.holderIl)}</div>`:""}</td>
      <td>${esc(r.type||"—")}</td><td>${esc(r.territory||"—")}</td>
      <td>${r.expiry?fmtDate(r.expiry):(r.trigger==="None / perpetual"?"Perpetual":"—")}</td>
      <td><span class="tag ${rs.tag}">${esc(rs.label)}</span></td>
    </tr>`}).join("")||`<tr><td colspan="6"><div class="empty">No records match this filter.</div></td></tr>`;
}

/* ---------- title drawer ---------- */
document.querySelectorAll("#dTabs button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#dTabs button").forEach(x=>x.classList.toggle("on",x===b));
  document.querySelectorAll(".dtab").forEach(x=>x.classList.toggle("on",x.id==="t-"+b.dataset.t));
});
function openTitle(id,tab){
  editingId=id;
  const t=id?db.titles.find(x=>x.id===id):{};
  $("dTitle").textContent=id?t.title:"New title";
  $("dSku").textContent=t.sku||"SKU assigned on save";
  $("dDel").style.display=id?"":"none";
  const r=t.rights||{},y=t.royalty||{};
  const set=(i,v)=>{$(i).value=v??""};
  $("f_lang").innerHTML=LANGS.map(l=>`<option>${l}</option>`).join("");
  $("f_base").innerHTML='<option value=""></option>'+LANGS.map(l=>`<option>${l}</option>`).join("");
  set("f_title",t.title);set("f_eng",t.englishTitle);set("f_lang",t.language||"English");set("f_base",t.baseLanguage);
  set("f_catg",t.category||"Children");set("f_age",t.age||"6+");set("f_isbn",t.isbn);set("f_fmt",t.format||"Print");set("f_series",t.series);
  set("f_author",t.author);set("f_illus",t.illustrator);set("f_trans",t.translator);set("f_editor",t.editor);
  set("f_year",t.yearPub);set("f_mrp",t.mrp);set("f_stat",t.status||"In Print");
  set("f_reprints",(t.reprints||[]).map(r=>r.year+", "+r.qty).join("\n"));
  set("f_themes",(t.themes||[]).join(", "));set("f_bigidea",t.bigIdea);set("f_grades",(t.grades||[]).join(", "));set("f_subjects",(t.subjects||[]).join(", "));set("f_blurb",t.blurbShort);set("f_blurblong",t.blurbLong);set("f_skills",(t.skills||[]).join(", "));set("f_spice",(t.spice||[]).join(", "));set("f_readlevel",t.readingLevel);set("f_vibgyor",t.vibgyor);
  set("f_pages",t.pages);set("f_dimL",t.dimL);set("f_dimB",t.dimB);set("f_dimW",t.dimW);set("f_weight",t.weight);set("f_printm",t.printMethod);set("f_printer",t.printer);set("f_portal",t.portalLink);
  set("f_seot",t.seoTitle);set("f_seok",t.seoKeywords);set("f_seod",t.seoDesc);
  set("f_pdf",t.pdfLink);set("f_asin",t.asin);set("f_dist1",t.distPrimary);set("f_dist2",t.distOther);
  pendingCover=undefined;$("f_coverfile").value="";set("f_coverurl",t.coverUrl);coverPreview();
  set("f_awards",(t.awards||[]).map(a=>a.name+", "+a.year).join("\n"));
  set("r_holder",r.holder);set("r_holderIl",r.holderIl);set("r_year",r.year);set("r_type",r.type);
  set("r_terr",r.territory);set("r_exp",r.expiry);set("r_trig",r.trigger);set("r_contract",r.contractRef);
  set("r_notice",r.notice);set("r_src",r.source);set("r_cc",r.cc);set("r_notes",r.notes);
  set("y_print",y.ratePrint);set("y_ebook",y.rateEbook);set("y_base",y.base);set("y_split",y.split);
  set("y_adv",y.advance);set("y_rec",y.recouped);set("y_notes",y.notes);
  $("mrpHist").innerHTML=(t.mrpHistory||[]).slice(-4).map(h=>
    `<div class="hist">MRP ₹${h.from??"—"} → ₹${h.to} on ${fmtDate(h.ts)}</div>`).join("");
  document.querySelectorAll("#dTabs button").forEach(x=>x.classList.toggle("on",x.dataset.t===(tab||"bib")));
  document.querySelectorAll(".dtab").forEach(x=>x.classList.toggle("on",x.id==="t-"+(tab||"bib")));
  $("dbg").classList.add("on");$("drawer").classList.add("on");
}
function closeDrawer(){$("dbg").classList.remove("on");$("drawer").classList.remove("on");editingId=null}
function parsePairs(txt){return String(txt||"").split("\n").map(l=>l.split(",").map(s=>s.trim())).filter(p=>p[0]).map(p=>({a:p[0],b:p[1]||""}))}
function saveTitle(){
  if(!canEdit())return;
  const title=$("f_title").value.trim();
  if(!title)return toast("A title is required");
  let t=editingId?db.titles.find(x=>x.id===editingId):null;
  const isNew=!t;
  if(isNew){t={id:uid(),createdAt:Date.now()};db.titles.push(t)}
  const oldMrp=t.mrp;
  Object.assign(t,{
    title,englishTitle:$("f_eng").value.trim(),language:$("f_lang").value,baseLanguage:$("f_base").value,
    category:$("f_catg").value,age:$("f_age").value,isbn:$("f_isbn").value.trim(),format:$("f_fmt").value,series:$("f_series").value.trim(),
    author:$("f_author").value.trim(),illustrator:$("f_illus").value.trim(),translator:$("f_trans").value.trim(),editor:$("f_editor").value.trim(),
    yearPub:+$("f_year").value||null,mrp:+$("f_mrp").value||null,status:$("f_stat").value,
    reprints:parsePairs($("f_reprints").value).map(p=>({year:p.a,qty:p.b})),
    themes:$("f_themes").value.split(",").map(s=>s.trim()).filter(Boolean),
    bigIdea:$("f_bigidea").value.trim(),
    grades:$("f_grades").value.split(",").map(s=>s.trim()).filter(Boolean),
    subjects:$("f_subjects").value.split(",").map(s=>s.trim()).filter(Boolean),
    blurbShort:$("f_blurb").value.trim(),blurbLong:$("f_blurblong").value.trim(),
    skills:$("f_skills").value.split(",").map(s=>s.trim()).filter(Boolean),
    spice:$("f_spice").value.split(",").map(s=>s.trim()).filter(Boolean),
    readingLevel:$("f_readlevel").value.trim(),vibgyor:$("f_vibgyor").value.trim(),
    pages:+$("f_pages").value||null,dimL:+$("f_dimL").value||null,dimB:+$("f_dimB").value||null,dimW:+$("f_dimW").value||null,weight:+$("f_weight").value||null,
    printMethod:$("f_printm").value.trim(),printer:$("f_printer").value.trim(),portalLink:$("f_portal").value.trim(),
    seoTitle:$("f_seot").value.trim(),seoKeywords:$("f_seok").value.trim(),seoDesc:$("f_seod").value.trim(),
    pdfLink:$("f_pdf").value.trim(),asin:$("f_asin").value.trim(),distPrimary:$("f_dist1").value.trim(),distOther:$("f_dist2").value.trim(),
    coverUrl:$("f_coverurl").value.trim(),
    awards:parsePairs($("f_awards").value).map(p=>({name:p.a,year:p.b})),
    rights:{holder:$("r_holder").value.trim(),holderIl:$("r_holderIl").value.trim(),year:+$("r_year").value||null,
      type:$("r_type").value,territory:$("r_terr").value,expiry:$("r_exp").value,trigger:$("r_trig").value,
      contractRef:$("r_contract").value.trim(),notice:$("r_notice").value.trim(),source:$("r_src").value.trim(),
      cc:$("r_cc").value,notes:$("r_notes").value.trim()},
    royalty:{ratePrint:+$("y_print").value||null,rateEbook:+$("y_ebook").value||null,base:$("y_base").value,
      split:$("y_split").value.trim(),advance:+$("y_adv").value||null,recouped:+$("y_rec").value||null,notes:$("y_notes").value.trim()},
    updatedAt:Date.now()
  });
  if(pendingCover!==undefined)t.cover=pendingCover||"";
  if(!t.sku)t.sku=makeSKU(t);
  if(!isNew&&oldMrp!==t.mrp&&t.mrp){t.mrpHistory=t.mrpHistory||[];t.mrpHistory.push({from:oldMrp,to:t.mrp,ts:Date.now()})}
  logAct(isNew?"Added":"Updated",t.title);
  persist();closeDrawer();renderCat();renderDash();renderRights();
  toast((isNew?"Added ":"Saved ")+t.title);
}
function deleteTitle(){
  if(!canEdit())return;
  if(!editingId)return;
  const t=db.titles.find(x=>x.id===editingId);
  if(!confirm(`Delete “${t.title}” permanently?`))return;
  db.titles=db.titles.filter(x=>x.id!==editingId);
  logAct("Deleted",t.title);persist();closeDrawer();renderCat();renderDash();renderRights();
  toast("Deleted "+t.title);
}


/* ---------- cover images ---------- */
let pendingCover; // undefined = no change, null = remove, string = new data URL
function coverSrc(t){return (t&&(t.cover||t.coverUrl))||""}
function coverPreview(){
  const url=$("f_coverurl").value.trim();
  const cur=editingId?((db.titles.find(x=>x.id===editingId)||{}).cover||""):"";
  const src=(pendingCover!==undefined?(pendingCover||""):cur)||url;
  const p=$("coverPrev");
  p.innerHTML=src?'<img src="'+esc(src)+'" style="width:100%;height:100%;object-fit:cover" onerror="this.parentNode.textContent=\'Link not loading\'">':"No cover";
}
function coverUpload(){
  if(!canEdit())return;
  const f=$("f_coverfile").files[0];
  if(!f)return;
  const img=new Image();
  img.onload=()=>{
    const W=320,scale=Math.min(1,W/img.width);
    const c=document.createElement("canvas");
    c.width=Math.round(img.width*scale);c.height=Math.round(img.height*scale);
    c.getContext("2d").drawImage(img,0,0,c.width,c.height);
    pendingCover=c.toDataURL("image/jpeg",0.72);
    URL.revokeObjectURL(img.src);
    coverPreview();toast("Cover ready — click Save title to keep it");
  };
  img.onerror=()=>toast("That file could not be read as an image");
  img.src=URL.createObjectURL(f);
}
function coverRemove(){
  if(!canEdit())return;
  pendingCover=null;$("f_coverurl").value="";$("f_coverfile").value="";
  coverPreview();toast("Cover will be removed when you save");
}

/* ---------- catalogue generator ---------- */
function setLay(el){genLayout=el.dataset.lay;document.querySelectorAll("[data-lay]").forEach(c=>c.classList.toggle("on",c===el));renderGen()}
const genSel={themes:new Set(),series:new Set(),bigIdeas:new Set(),grades:new Set(),subjects:new Set(),skills:new Set(),spice:new Set()};
const FACETS=[
  {key:"themes",el:"fx_themes",get:t=>t.themes||[],ph:"Search themes…",empty:"No themes yet — import your stock Excel file (it has a Theme column) or add themes in any title's Discovery section."},
  {key:"series",el:"fx_series",get:t=>t.series?[t.series]:[],ph:"Search series…",empty:"No series yet — import your stock file (its Category column holds series like ILR, Picture Book) or set Series on titles."},
  {key:"bigIdeas",el:"fx_bigIdeas",get:t=>t.bigIdea?[t.bigIdea]:[],ph:"Search big ideas…",empty:"No big ideas yet — add one to titles in the Discovery section."},
  {key:"grades",el:"fx_grades",get:t=>t.grades||[],ph:"Search grades…",empty:"No grades yet — import your stock file (it has a Grade column) or add grades to titles.",gradeSort:true},
  {key:"subjects",el:"fx_subjects",get:t=>t.subjects||[],ph:"Search subjects…",empty:"No subjects yet — add subjects to titles in the Discovery section."},
  {key:"skills",el:"fx_skills",get:t=>t.skills||[],ph:"Search skills…",empty:"No skills yet — import the master backlist file or add skills to titles."},
  {key:"spice",el:"fx_spice",get:t=>t.spice||[],ph:"Search SPICE…",empty:"No SPICE values yet — import the master backlist file or add them to titles."}
];
function facetCounts(f){
  const m=new Map(); // lower → {disp,count}
  db.titles.forEach(t=>f.get(t).forEach(v=>{
    v=String(v).trim();if(!v)return;
    const k=v.toLowerCase();
    const e=m.get(k);
    if(e){e.count++;}else m.set(k,{disp:v,count:1});
  }));
  let arr=[...m.values()];
  if(f.gradeSort){
    arr.sort((a,b)=>{const na=parseInt(a.disp),nb=parseInt(b.disp);
      if(!isNaN(na)&&!isNaN(nb))return na-nb;if(!isNaN(na))return 1;if(!isNaN(nb))return -1;
      return a.disp.localeCompare(b.disp)});
  }else arr.sort((a,b)=>b.count-a.count||a.disp.localeCompare(b.disp));
  return arr;
}
function genFiltered(){
  const L=$("gLang").value,C=$("gCatg").value,S=$("gStat").value;
  const q=($("gSearch")&&$("gSearch").value||"").trim().toLowerCase();
  const has=(set,vals)=>set.size===0||vals.some(v=>set.has(String(v).toLowerCase()));
  return db.titles.filter(t=>
    (!L||t.language===L)&&(!C||t.category===C)&&(!S||t.status===S)&&
    (!q||[t.title,t.englishTitle,t.author,t.illustrator,t.translator,t.series,t.bigIdea,t.blurbShort,t.isbn,(t.themes||[]).join(" "),(t.subjects||[]).join(" "),(t.grades||[]).join(" "),(t.skills||[]).join(" "),(t.spice||[]).join(" "),t.readingLevel,t.vibgyor].join(" ").toLowerCase().includes(q))&&
    has(genSel.themes,t.themes||[])&&
    has(genSel.series,t.series?[t.series]:[])&&
    has(genSel.bigIdeas,t.bigIdea?[t.bigIdea]:[])&&
    has(genSel.grades,t.grades||[])&&
    has(genSel.subjects,t.subjects||[])&&
    has(genSel.skills,t.skills||[])&&
    has(genSel.spice,t.spice||[])
  ).sort((a,b)=>String(a.title).localeCompare(b.title));
}
function renderGenChips(){
  FACETS.forEach(f=>{
    const host=$(f.el);if(!host)return;
    const all=facetCounts(f);
    const dispOf=k=>{const e=all.find(x=>x.disp.toLowerCase()===k);return e?e.disp:k};
    if(all.length===0&&genSel[f.key].size===0){
      host.innerHTML=`<span class="note">${f.empty}</span>`;return;
    }
    host.innerHTML=`
      <div class="fx-sel">${[...genSel[f.key]].map(k=>
        `<span class="fx-chip">${esc(dispOf(k))}<button onclick="fxRemove('${f.key}','${esc(k).replace(/'/g,"\\'")}')" aria-label="Remove">×</button></span>`).join("")}</div>
      <input class="fx-input" placeholder="${f.ph}" id="fxin_${f.key}"
        oninput="fxList('${f.key}')" onfocus="fxList('${f.key}')">
      <div class="fx-dd" id="fxdd_${f.key}"></div>`;
  });
}
function fxList(key){
  document.querySelectorAll(".fx-dd").forEach(d=>{if(d.id!=="fxdd_"+key)d.classList.remove("open")});
  const f=FACETS.find(x=>x.key===key);
  const q=($("fxin_"+key).value||"").trim().toLowerCase();
  const all=facetCounts(f).filter(e=>!genSel[key].has(e.disp.toLowerCase())&&(!q||e.disp.toLowerCase().includes(q)));
  const dd=$("fxdd_"+key);
  dd.innerHTML=all.slice(0,40).map(e=>
    `<button class="fx-opt" onclick="fxAdd('${key}','${esc(e.disp.toLowerCase()).replace(/'/g,"\\'")}')"><span>${esc(e.disp)}</span><span class="cnt">${e.count}</span></button>`
  ).join("")||`<div class="fx-none">${q?"No matches for “"+esc(q)+"”":"Nothing more to add"}</div>`;
  dd.classList.add("open");
}
function fxAdd(key,k){genSel[key].add(k);renderGen()}
function fxRemove(key,k){genSel[key].delete(k);renderGen()}
document.addEventListener("click",e=>{
  const f=e.target.closest(".facet");
  document.querySelectorAll(".fx-dd").forEach(d=>{if(!f||!f.contains(d))d.classList.remove("open")});
});
document.addEventListener("keydown",e=>{
  if(e.key==="Escape")document.querySelectorAll(".fx-dd").forEach(d=>d.classList.remove("open"));
});
function getInc(){
  const g=id=>{const e=$(id);return e?e.checked:true};
  return{cover:g("incCover"),price:g("incPrice"),isbn:g("incIsbn"),contrib:g("incContrib"),ped:g("incPed"),specs:$("incSpecs")&&$("incSpecs").checked,
    summary:($("incSummary")&&$("incSummary").value)||"short"};
}
function catHTML(rows){
  const inc=getInc();
  const title=esc($("gTitle").value||"Katha Books"),sub=esc($("gSub").value),foot=esc($("gFoot").value);
  const today=new Date().toLocaleDateString("en-IN",{day:"numeric",month:"long",year:"numeric"});
  let items="";
  rows.forEach(t=>{
    const meta=inc.contrib?[t.author&&("By "+t.author),t.illustrator&&("Illustrated by "+t.illustrator),t.translator&&("Translated by "+t.translator)].filter(Boolean).join(" · "):"";
    const ped=inc.ped?[t.series,(t.grades||[]).length?("Grades "+t.grades.join(", ")):"",(t.subjects||[]).slice(0,3).join(", "),(t.skills||[]).slice(0,3).join(", "),(t.themes||[]).slice(0,3).join(", "),t.bigIdea?("Big idea: "+t.bigIdea):"",t.readingLevel].filter(Boolean).join("  ·  "):"";
    const specs=inc.specs?[t.pages?(t.pages+" pp"):"",(t.dimL&&t.dimB)?(t.dimL+" × "+t.dimB+(t.dimW?" × "+t.dimW:"")+" cm"):"",t.weight?(t.weight+" g"):"",t.printMethod].filter(Boolean).join("  ·  "):"";
    const meta2=[t.language,t.category&&(t.category+(t.age?" "+t.age:"")),inc.isbn&&t.isbn?("ISBN "+t.isbn):""].filter(Boolean).join("  ·  ");
    const summaryTxt=inc.summary==="none"?"":(inc.summary==="long"?(t.blurbLong||t.blurbShort):(t.blurbShort||""));
    if(genLayout==="compact"){
      items+=`<div class="cat-item" style="padding:8px 0"><div class="spinebar"></div><div style="flex:1;display:flex;justify-content:space-between;gap:14px;align-items:baseline"><div><h4 style="font-size:14.5px;display:inline">${esc(t.title)}</h4>${meta?` <span class="meta" style="display:inline">— ${esc(meta)}</span>`:""}<div class="meta">${esc([meta2,ped].filter(Boolean).join("  ·  "))}</div></div><div class="price">${inc.price&&t.mrp?"₹"+t.mrp:""}</div></div></div>`;
    }else{
      items+=`<div class="cat-item"><div class="spinebar"></div>${inc.cover&&coverSrc(t)?`<img src="${esc(coverSrc(t))}" style="width:58px;height:78px;object-fit:cover;border-radius:5px;flex-shrink:0">`:""}<div style="flex:1"><div style="display:flex;justify-content:space-between;gap:14px"><h4>${esc(t.title)}</h4><div class="price">${inc.price&&t.mrp?"₹"+t.mrp:""}</div></div>${meta?`<div class="meta">${esc(meta)}</div>`:""}<div class="meta" style="color:var(--ink-3)">${esc(meta2)}</div>${ped?`<div class="meta" style="color:var(--ink-3)">${esc(ped)}</div>`:""}${specs?`<div class="meta" style="color:var(--ink-3)">${esc(specs)}</div>`:""}${summaryTxt?`<div class="blurb">${esc(summaryTxt)}</div>`:""}</div></div>`;
    }
  });
  return `<div class="cat-head"><div class="eyebrow">Katha · Thematic catalogue</div><h1>${title}</h1><p>${sub?sub+" · ":""}${rows.length} titles · ${today}</p></div>${items||'<p style="color:var(--ink-3);padding:20px 0">No titles match the current filters.</p>'}<div class="cat-foot"><span>${foot}</span><span>Generated ${today}</span></div>`;
}
function renderGen(){renderGenChips();const rows=genFiltered();$("gCount").textContent=rows.length+" titles will appear in this catalogue.";$("gPrev").innerHTML=catHTML(rows)}
function doPrint(){
  $("printArea").innerHTML='<div style="max-width:760px;margin:0 auto;font-family:var(--sans)">'+catHTML(genFiltered())+"</div>";
  document.body.classList.add("printing");
  window.print();
  setTimeout(()=>document.body.classList.remove("printing"),400);
}
function exportHTML(){
  const css=document.querySelector("style").textContent;
  const html=`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc($("gTitle").value)}</title><link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,400;9..144,600&display=swap" rel="stylesheet"><style>${css}\nbody{background:#fff;padding:34px}</style></head><body><div style="max-width:760px;margin:0 auto">${catHTML(genFiltered())}</div></body></html>`;
  dl(new Blob([html],{type:"text/html"}),"katha-catalogue.html");
  toast("Catalogue HTML downloaded");
}

/* ---------- import / export ---------- */
function dl(blob,name){const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),5000)}
const HEADMAP={title:["title","book title","bengali title","native title"],englishTitle:["english title"],language:["language","lang"],
  category:["children/young adult","children/ young adult","children / ya","children/ya","series"],series:["category","300m series"],author:["author","authors"],
  illustrator:["illustrator","illustrators"],translator:["translator","translated by"],
  editor:["edited by","editor","edited by outside katha","edited by (outside katha)"],
  status:["availability","status"],mrp:["price","mrp","price (rs)","price rs","price (as per kand)"],isbn:["isbn","isbn no.","isbn no","isbn13","isbn-13"],
  pdfLink:["pdf link","pdf"],themes:["theme","themes","themes / keywords","themes/keywords"],age:["age","age group"],bigIdea:["big idea","bigidea"],grades:["grade","grades","grade/class"],subjects:["subject","subjects"],yearPub:["yr pub.","yr pub","year","year of publication","published year"],
  asin:["asin"],kbId:["kb id","kbid"],coverUrl:["cover","cover url","cover image","image","image url"],
  blurbShort:["catalog summary","catalogue summary","short blurb","blurb"],blurbLong:["story description","long description","full summary"],
  skills:["skills"],spice:["spice"],readingLevel:["reading level"],vibgyor:["vibgyor level"],
  pages:["total pages (excl. cover)","total pages","pages"],dimL:["length (cm)","length"],dimB:["breadth (cm)","breadth"],dimW:["width (cm)","spine width"],
  weight:["weight (g)","wt","weight"],printMethod:["printing method"],printer:["printer name","printer"],portalLink:["portal link"],lastReprint:["last reprint year"],stock:["quantity","stock","qty"]};
function mapRow(row){
  const out={};const keys=Object.keys(row);
  for(const[field,names]of Object.entries(HEADMAP)){
    const k=keys.find(k=>names.includes(String(k).trim().toLowerCase()));
    if(k!=null&&row[k]!=null&&row[k]!=="")out[field]=row[k];
  }
  return out;
}
function importExcel(){
  if(!canEdit())return;
  const f=$("impFile").files[0];
  if(!f)return toast("Choose an .xlsx file first");
  const rd=new FileReader();
  rd.onload=e=>{
    try{
      const wb=XLSX.read(e.target.result,{type:"array"});
      let added=0,updated=0;
      wb.SheetNames.forEach(sn=>{
        const grid=XLSX.utils.sheet_to_json(wb.Sheets[sn],{header:1,defval:""});
        let hr=-1;
        for(let i=0;i<Math.min(5,grid.length);i++){
          const low=grid[i].map(c=>String(c).trim().toLowerCase());
          if(low.some(c=>c.includes("title"))){hr=i;break}
        }
        if(hr<0)return;
        const head=grid[hr].map(c=>String(c).trim());
        const ws=wb.Sheets[sn];
        const pdfCol=head.findIndex(h=>/^pdf/i.test(h));
        const rows=grid.slice(hr+1).map((arr,ri)=>{
          const o={};head.forEach((h,i)=>{if(h)o[h]=arr[i]});
          if(pdfCol>=0){
            const cell=ws[XLSX.utils.encode_cell({r:hr+1+ri,c:pdfCol})];
            if(cell&&cell.l&&cell.l.Target)o[head[pdfCol]]=cell.l.Target;
            else if(String(o[head[pdfCol]]||"").trim().toLowerCase()==="pdf link")o[head[pdfCol]]="";
          }
          return o;
        });
        rows.forEach(raw=>{
          const m=mapRow(raw);
          if(!m.title&&!m.englishTitle)return;
          let titleRaw=String(m.title||"").trim();
          if(!titleRaw&&m.englishTitle)titleRaw=String(m.englishTitle).trim();
          const title=titleRaw;
          if(title.length<2||/^\(?blank\)?(\s*total)?$/i.test(title)||/^(grand\s+)?total$/i.test(title)||/^s\.?\s*no\.?$/i.test(title))return;
          let lang=String(m.language||"").trim();
          lang=LANGS.find(l=>l.toLowerCase()===lang.toLowerCase())||lang||"English";
          let t=db.titles.find(x=>x.title.toLowerCase()===title.toLowerCase()&&x.language===lang);
          const isNew=!t;
          if(isNew){t={id:uid(),createdAt:Date.now(),title,language:lang};db.titles.push(t);added++}else updated++;
          if(m.englishTitle)t.englishTitle=String(m.englishTitle).trim();
          if(m.category){const c=String(m.category).toLowerCase();t.category=/young/.test(c)?"Young Adult":/adult/.test(c)?"Adult":"Children"}
          if(m.author)t.author=String(m.author).trim();
          if(m.illustrator)t.illustrator=String(m.illustrator).trim();
          if(m.translator)t.translator=String(m.translator).trim();
          if(m.editor)t.editor=String(m.editor).trim();
          if(m.status)t.status=normStatus(m.status);
          if(m.mrp){const p=parseFloat(String(m.mrp).replace(/[^\d.]/g,""));if(p)t.mrp=Math.round(p)}
          if(m.isbn){let i=String(m.isbn).replace(/[^\dXx]/g,"");t.isbn=i}
          if(m.pdfLink)t.pdfLink=String(m.pdfLink).trim();
          if(m.themes)t.themes=String(m.themes).split(/[,;]/).map(s=>s.trim().replace(/\.+$/,"")).filter(Boolean);
          if(m.series)t.series=String(m.series).trim();
          if(m.bigIdea)t.bigIdea=String(m.bigIdea).trim();
          if(m.grades)t.grades=[...new Set(String(m.grades).split(/[,;/]/).map(s=>s.trim().replace(/\.+$/,"").replace(/^grade\s*/i,"")).filter(Boolean))];
          if(m.subjects)t.subjects=String(m.subjects).split(/[,;/]/).map(s=>s.trim().replace(/\.+$/,"")).filter(Boolean);
          if(m.age){const a=String(m.age);const n=a.match(/\d+/);t.age=/adult/i.test(a)?"18+":(n?n[0]+"+":t.age)}
          if(m.yearPub){const y=parseInt(m.yearPub);if(y>1900)t.yearPub=y}
          if(m.asin)t.asin=String(m.asin).trim();
          if(m.coverUrl&&/^https?:/i.test(String(m.coverUrl).trim()))t.coverUrl=String(m.coverUrl).trim();
          if(m.blurbShort)t.blurbShort=String(m.blurbShort).trim();
          if(m.blurbLong)t.blurbLong=String(m.blurbLong).trim();
          if(m.skills)t.skills=String(m.skills).split(/[,;]/).map(s=>s.trim().replace(/\.+$/,"")).filter(Boolean);
          if(m.spice)t.spice=String(m.spice).split(/[,;]/).map(s=>s.trim().replace(/\.+$/,"")).filter(Boolean);
          if(m.readingLevel)t.readingLevel=String(m.readingLevel).trim();
          if(m.vibgyor)t.vibgyor=String(m.vibgyor).trim();
          if(m.pages){const p=parseInt(m.pages);if(p>0)t.pages=p}
          if(m.dimL){const v=parseFloat(m.dimL);if(v>0)t.dimL=v}
          if(m.dimB){const v=parseFloat(m.dimB);if(v>0)t.dimB=v}
          if(m.dimW){const v=parseFloat(m.dimW);if(v>0)t.dimW=v}
          if(m.weight){const v=parseFloat(m.weight);if(v>0)t.weight=v}
          if(m.printMethod)t.printMethod=String(m.printMethod).trim();
          if(m.printer)t.printer=String(m.printer).trim();
          if(m.portalLink&&/^https?:/i.test(String(m.portalLink).trim()))t.portalLink=String(m.portalLink).trim();
          if(m.lastReprint){const y=parseInt(m.lastReprint);if(y>1900){t.reprints=t.reprints||[];if(!t.reprints.some(r=>String(r.year)===String(y)))t.reprints.push({year:String(y),qty:""})}}
          if(m.kbId)t.kbId=String(m.kbId).trim();
          if(/wikimedia/i.test(t.illustrator||"")){t.rights=t.rights||{};t.rights.holderIl=t.rights.holderIl||"Wikimedia Commons";t.rights.cc=t.rights.cc||"Unknown — needs checking"}
          if(!t.status)t.status="In Print";
          if(!t.sku)t.sku=makeSKU(t);
          t.updatedAt=Date.now();
        });
      });
      logAct("Imported",`${added} added, ${updated} updated from ${f.name}`);
      persist();renderDash();renderCat();renderRights();renderGen();
      toast(`Imported: ${added} new, ${updated} updated`);
      $("impFile").value="";
    }catch(err){toast("Could not read that file — is it a valid .xlsx?")}
  };
  rd.readAsArrayBuffer(f);
}
function exportExcel(){
  const cat=db.titles.map(t=>({SKU:t.sku,Title:t.title,"English title":t.englishTitle,Language:t.language,
    "Base language":t.baseLanguage,Category:t.category,Series:t.series,Age:t.age,Format:t.format,ISBN:t.isbn,
    Author:t.author,Illustrator:t.illustrator,Translator:t.translator,"Edited by":t.editor,
    "Year pub":t.yearPub,"MRP":t.mrp,Status:t.status,Themes:(t.themes||[]).join(", "),"Big idea":t.bigIdea,Grades:(t.grades||[]).join(", "),Subjects:(t.subjects||[]).join(", "),
    "Short blurb":t.blurbShort,"Story description":t.blurbLong,Skills:(t.skills||[]).join(", "),SPICE:(t.spice||[]).join(", "),"Reading level":t.readingLevel,"ViBGYOR":t.vibgyor,Pages:t.pages,"Length cm":t.dimL,"Breadth cm":t.dimB,"Width cm":t.dimW,"Weight g":t.weight,"Printing method":t.printMethod,Printer:t.printer,"Portal link":t.portalLink,"SEO title":t.seoTitle,"SEO keywords":t.seoKeywords,"SEO description":t.seoDesc,
    "PDF link":t.pdfLink,"Cover URL":t.coverUrl,ASIN:t.asin,"KB ID":t.kbId,"Primary distributor":t.distPrimary,"Other distributors":t.distOther,
    Awards:(t.awards||[]).map(a=>a.name+" "+a.year).join("; "),Reprints:(t.reprints||[]).map(r=>r.year+":"+r.qty).join("; ")}));
  const rts=db.titles.map(t=>{const r=t.rights||{};return{SKU:t.sku,Title:t.title,Language:t.language,
    "Copyright holder":r.holder,"Illustration holder":r.holderIl,"Copyright year":r.year,"Rights type":r.type,
    Territory:r.territory,"Expiry":r.expiry,"Reversion trigger":r.trigger,"Contract link":r.contractRef,
    "Notice":r.notice,"Source licence":r.source,"CC type":r.cc,Notes:r.notes}});
  const roy=db.titles.map(t=>{const y=t.royalty||{};return{SKU:t.sku,Title:t.title,
    "Rate print %":y.ratePrint,"Rate ebook %":y.rateEbook,Base:y.base,Split:y.split,
    "Advance ₹":y.advance,"Recouped ₹":y.recouped,Notes:y.notes}});
  const wb=XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(cat),"Catalogue");
  XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(rts),"Rights");
  XLSX.utils.book_append_sheet(wb,XLSX.utils.json_to_sheet(roy),"Royalty");
  XLSX.writeFile(wb,"katha-catalogue-export.xlsx");
  toast("Excel workbook downloaded");
}
function exportJSON(){const out=Object.assign({},db,{_users:getUsers()});dl(new Blob([JSON.stringify(out,null,1)],{type:"application/json"}),"katha-backup-"+new Date().toISOString().slice(0,10)+".json");toast("Backup downloaded (includes team accounts) — keep it safe")}
function restoreJSON(){
  if(!canEdit())return;
  const f=$("resFile").files[0];
  if(!f)return toast("Choose a backup .json file first");
  const rd=new FileReader();
  rd.onload=e=>{try{
    const d=JSON.parse(e.target.result);
    if(!d.titles)throw 0;
    if(d._users&&d._users.length&&confirm("This backup includes "+d._users.length+" team account(s). Restore those too? (Cancel keeps the accounts already on this device)"))setUsers(d._users);
    delete d._users;db=d;persist();renderDash();renderCat();renderRights();renderGen();
    toast("Backup restored — "+db.titles.length+" titles");
  }catch(_){toast("That file is not a valid Katha backup")}};
  rd.readAsText(f);
}
function wipeAll(){
  if(!canEdit())return;
  if(!confirm("Erase ALL data on this device? Export a backup first if you need one."))return;
  db={meta:{seq:0,updatedAt:null},titles:[],activity:[]};
  persist();renderDash();renderCat();renderRights();renderGen();
  toast("All data erased");
}

/* ---------- sample data ---------- */
function loadSample(){
  if(!canEdit())return;
  const S=[
    {title:"The Whispering Palms",language:"English",category:"Children",age:"6+",author:"Geeta Dharmarajan",illustrator:"Atanu Roy",yearPub:2019,mrp:195,status:"In Print",themes:["Environment","Coastal life"],series:"Picture Book",bigIdea:"Interdependence",grades:["2","3","4"],subjects:["EVS","Language"],blurbShort:"A young girl in a fishing village learns to listen to what the palms have been saying all along — a gentle story about noticing the natural world.",isbn:"9788189934521",rights:{holder:"Geeta Dharmarajan",holderIl:"Atanu Roy",year:2019,type:"All rights",territory:"World",trigger:"None / perpetual",notice:"© 2019 Geeta Dharmarajan · Illustrations © 2019 Atanu Roy"},royalty:{ratePrint:10,base:"MRP (cover price)"}},
    {title:"Nani Ki Kahaniyan",language:"Hindi",category:"Children",age:"3+",author:"Mamta Nainy",illustrator:"Wikimedia Commons",yearPub:2017,mrp:150,status:"In Print",themes:["Folk tales","Family"],blurbShort:"दादी-नानी की कहानियों का संग्रह — हर शाम एक नई कहानी।",isbn:"9788189934668"},
    {title:"Ondu Kadina Kathe",language:"Kannada",category:"Children",age:"6+",author:"Sudha Murthy",illustrator:"Priya Kuriyan",translator:"H S Raghavendra Rao",yearPub:2015,mrp:175,status:"Reprint Planned",themes:["Environment","Forests"],bigIdea:"Interdependence",grades:["3","4","5"],subjects:["EVS","Science"],blurbShort:"ಕಾಡಿನ ಪ್ರಾಣಿಗಳ ಜೊತೆ ಒಂದು ದಿನ — ಮಕ್ಕಳಿಗಾಗಿ ಪರಿಸರ ಕಥೆ.",isbn:"9788189934779",rights:{holder:"Sudha Murthy",type:"Print + digital",territory:"India only",expiry:"2026-11-30",trigger:"End of term",notice:"© 2015 Sudha Murthy"}},
    {title:"Kadal Paadum Paattu",language:"Tamil",category:"Children",age:"9+",author:"Salma",illustrator:"Trotsky Marudu",yearPub:2021,mrp:225,status:"In Print",themes:["Coastal life","Music"],blurbShort:"கடலோர கிராமத்தில் பாடல்களின் வழியே வாழ்க்கையை கற்றுக்கொள்ளும் சிறுமி.",isbn:"9788189934882",rights:{holder:"Salma",type:"All rights",territory:"World",trigger:"None / perpetual"}},
    {title:"Letters to Amma",language:"English",category:"Young Adult",age:"12+",author:"Paro Anand",yearPub:2008,mrp:250,status:"Out of Print",themes:["Identity","Family"],bigIdea:"Identity",grades:["8","9","10"],subjects:["Language","Social Studies"],blurbShort:"A teenager writes letters she never sends, working out who she is becoming. Shortlisted for the Crossword Book Award.",isbn:"9788189934995",awards:[{name:"Crossword Book Award shortlist",year:"2009"}],rights:{holder:"Paro Anand",type:"Print only",territory:"Indian subcontinent",expiry:"2026-09-15",trigger:"Out of print",notice:"© 2008 Paro Anand"},royalty:{ratePrint:10,base:"Net receipts",advance:25000,recouped:25000}},
    {title:"Chitra Ki Chidiya",language:"Hindi",category:"Children",age:"3+",author:"Kusum Lata",illustrator:"Suddhasattwa Basu",yearPub:2023,mrp:165,status:"In Print",themes:["Birds","Friendship"],bigIdea:"Friendship",grades:["KG","1","2"],subjects:["Language","Art"],blurbShort:"चित्रा और उसकी नन्ही चिड़िया की दोस्ती की प्यारी कहानी।",isbn:"9788189935015",rights:{holder:"Kusum Lata",holderIl:"Suddhasattwa Basu",type:"Print + digital + audio",territory:"World",trigger:"None / perpetual"},royalty:{ratePrint:10,rateEbook:20,base:"MRP (cover price)",split:"60 / 40"}}
  ];
  S.forEach(s=>{
    if(db.titles.some(t=>t.title===s.title&&t.language===s.language))return;
    s.id=uid();s.createdAt=Date.now();s.updatedAt=Date.now();s.format="Print";
    if(/wikimedia/i.test(s.illustrator||"")){s.rights=s.rights||{};s.rights.holderIl="Wikimedia Commons";s.rights.cc="Unknown — needs checking"}
    s.sku=makeSKU(s);db.titles.push(s);
  });
  logAct("Loaded","Sample titles");
  persist();renderDash();renderCat();renderRights();renderGen();
  toast("Sample titles loaded — explore freely, then erase when ready");
}

/* ---------- boot ---------- */
async function initApp(){
  const ok=await idbOpen();
  if(ok)await load();
  const before=db.titles.length;
  db.titles=db.titles.filter(t=>{const x=String(t.title||"").trim();return x.length>=2&&!/^\(?blank\)?(\s*total)?$/i.test(x)&&!/^(grand\s+)?total$/i.test(x)});
  if(db.titles.length!==before)persist();
  renderDash();renderCat();renderRights();renderGen();
  if("serviceWorker"in navigator&&location.protocol==="https:")
    navigator.serviceWorker.register("sw.js").catch(()=>{});
}
(function(){
  const d=$("loginDomain");
  if(d)d.textContent=location.hostname||"books.katha.org";
  const u=sessionUser();
  if(u){
    currentUser=u;
    $("loginScreen").classList.add("gone");
    applyRole();initApp();
  }else if(getUsers().length===0){
    $("setupCard").style.display="";
  }else{
    $("loginCard").style.display="";
  }
})();
