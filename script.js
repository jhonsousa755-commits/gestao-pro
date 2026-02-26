/**
 * @license
 * Copyright (c) 2026 Joanatã de Sousa Galvão.
 */

// --- 1. CORE PWA ---
const initPWA = () => {
    try {
        const manifest = {
            "name": "Gestão Pro",
            "short_name": "Gestão Pro",
            "start_url": window.location.href.split('?')[0],
            "display": "standalone",
            "background_color": "#020205",
            "theme_color": "#020205",
            "icons": [{"src": "https://cdn-icons-png.flaticon.com/512/1611/1611154.png", "sizes": "512x512", "type": "image/png"}]
        };
        document.getElementById('pwa-manifest').setAttribute('href', 'data:application/json;base64,' + btoa(JSON.stringify(manifest)));

        if ('serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) {
            const swCode = "self.addEventListener('fetch', e => e.respondWith(fetch(e.request).catch(() => caches.match(e.request))));";
            const swBlob = new Blob([swCode], {type: 'text/javascript'});
            navigator.serviceWorker.register(URL.createObjectURL(swBlob)).catch(() => {});
        }
    } catch (e) {}
};
initPWA();

// --- 2. UTILITÁRIOS ---
const escapeHTML = str => { const d = document.createElement('div'); d.textContent = str; return d.innerHTML; };

const debounce = (f, t = 500) => { 
    let timer; 
    return (...a) => { clearTimeout(timer); timer = setTimeout(() => f.apply(this, a), t); }; 
};

const bufToB64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const b64ToBuf = s => new Uint8Array(atob(s).split("").map(c => c.charCodeAt(0)));

// --- 3. INDEXEDDB ---
const DB_NAME = 'GestaoPro_Production_V5';
const STORE_NAME = 'secure_vault';
const openDB = () => new Promise((res, rej) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = e => e.target.result.createObjectStore(STORE_NAME, { keyPath: 'id' });
    req.onsuccess = e => res(e.target.result);
    req.onerror = e => rej(e.target.error);
});

async function saveToDB(obj) {
    const dbI = await openDB();
    return new Promise((res, rej) => {
        const tx = dbI.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        store.put({ id: 'active_session', ...obj });
        tx.oncomplete = () => res();
        tx.onerror = () => rej(tx.error);
    });
}

async function getFromDB() {
    const dbI = await openDB();
    return new Promise(res => {
        const req = dbI.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).get('active_session');
        req.onsuccess = () => res(req.result);
        req.onerror = () => res(null);
    });
}

// --- 4. CRIPTOGRAFIA ---
let sessionKey = null; 
let vaultSalt = null;
let db = { income: 0, items: [], tab: 'fixo', updatedAt: 0 };

async function deriveKey(pwd, salt) {
    const enc = new TextEncoder();
    const keyMat = await crypto.subtle.importKey("raw", enc.encode(pwd), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
        keyMat, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
}

async function encryptAndSave() {
    if (!sessionKey || !vaultSalt) return;
    db.updatedAt = Date.now();
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, sessionKey, enc.encode(JSON.stringify(db)));
    
    try {
        await saveToDB({ data: cipher, iv, salt: vaultSalt });
        refreshUI();
    } catch (e) { console.error("Critical: Storage failed."); }
}

async function handleAuth() {
    const btn = document.getElementById('authBtn');
    const pwdInput = document.getElementById('masterPassword');
    const pwd = pwdInput.value;
    if (!pwd) return;

    btn.innerText = "Protegendo Conexão..."; 
    btn.disabled = true;

    const vault = await getFromDB();
    
    setTimeout(async () => {
        try {
            if (!vault) {
                if (confirm("Deseja criar esta senha como sua chave permanente?")) {
                    vaultSalt = crypto.getRandomValues(new Uint8Array(16));
                    sessionKey = await deriveKey(pwd, vaultSalt);
                    db = { income: 0, items: [], tab: 'fixo', updatedAt: Date.now() };
                    await encryptAndSave();
                    unlockUI();
                } else { btn.innerText = "Acessar Carteira"; btn.disabled = false; }
            } else {
                vaultSalt = vault.salt;
                sessionKey = await deriveKey(pwd, vaultSalt);
                const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv: vault.iv }, sessionKey, vault.data);
                db = JSON.parse(new TextDecoder().decode(dec));
                unlockUI(); refreshUI();
            }
        } catch (e) { 
            alert("Acesso Negado: Chave Inválida."); 
            pwdInput.value = ''; btn.innerText = "Acessar Carteira"; btn.disabled = false; 
        }
    }, 100);
}

function unlockUI() { 
    document.getElementById('authOverlay').style.display = 'none'; 
    document.getElementById('mainApp').style.display = 'block'; 
    lucide.createIcons(); 
}

function toggleModal(id) { 
    const m = document.getElementById(id); 
    m.style.display = m.style.display === 'none' ? 'flex' : 'none'; 
    lucide.createIcons(); 
}

// --- 5. BACKUP ---
async function exportVault() {
    const v = await getFromDB(); if (!v) return;
    const data = { app: "GP", ver: "5.0", payload: { data: bufToB64(v.data), iv: bufToB64(v.iv), salt: bufToB64(v.salt) } };
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify(data)], {type: "application/json"}));
    a.download = `Cofre_GestaoPro_${new Date().getTime()}.gpro`; 
    a.click();
}

async function importVault(e) {
    const f = e.target.files[0]; if (!f) return;
    const reader = new FileReader();
    reader.onload = async (ev) => {
        try {
            const j = JSON.parse(ev.target.result);
            if (j.app !== "GP") throw new Error();
            await saveToDB({ data: b64ToBuf(j.payload.data), iv: b64ToBuf(j.payload.iv), salt: b64ToBuf(j.payload.salt) });
            location.reload();
        } catch (err) { alert("Backup inválido."); }
    };
    reader.readAsText(f);
}

// --- 6. GESTÃO FINANCEIRA ---
const saveIncome = debounce((v) => { db.income = parseFloat(v) || 0; encryptAndSave(); });
document.getElementById('incomeInput').addEventListener('input', e => saveIncome(e.target.value));

function setTab(t) {
    db.tab = t;
    ['fixo', 'planejado', 'poupanca'].forEach(x => {
        document.getElementById(`tab-${x}`).className = `flex-1 py-3 rounded-xl text-[9px] font-black uppercase transition-all tap-active ${db.tab === x ? 'tab-active-' + x : 'text-slate-500'}`;
    });
    document.getElementById('mainSubmitBtn').className = `px-7 rounded-2xl flex items-center justify-center shadow-lg tap-active ${t==='fixo'?'bg-indigo-600':t==='planejado'?'bg-amber-600':'bg-cyan-600'}`;
    document.getElementById('parcelaArea').style.display = t === 'planejado' ? 'block' : 'none';
    if (t === 'poupanca') document.getElementById('catInput').value = 'Investimento';
    encryptAndSave();
}

function addItem() {
    const di = document.getElementById('descInput'), vi = document.getElementById('valInput'), ci = document.getElementById('catInput').value, pc = parseInt(document.getElementById('parcelaCount').value) || 1;
    if (!di.value || isNaN(parseFloat(vi.value))) return;
    db.items.unshift({ id: Date.now(), desc: di.value.trim(), val: db.tab === 'planejado' ? parseFloat(vi.value) / pc : parseFloat(vi.value), type: db.tab, cat: ci, date: new Date().toLocaleDateString('pt-BR'), paid: false });
    di.value = ''; vi.value = ''; encryptAndSave();
}
function togglePaid(id) { db.items = db.items.map(i => i.id === id ? {...i, paid: !i.paid} : i); encryptAndSave(); }
function deleteItem(id) { if(confirm("Apagar permanentemente?")) { db.items = db.items.filter(i => i.id !== id); encryptAndSave(); } }
function resetData() { if(confirm("CUIDADO: Destruir banco de dados local?")) { indexedDB.deleteDatabase(DB_NAME); location.reload(); } }

// --- 7. INTERFACE ---
let chartInst = null;
function refreshUI() {
    const f = db.items.filter(i => i.type === 'fixo').reduce((a,b) => a + b.val, 0);
    const p = db.items.filter(i => i.type === 'planejado').reduce((a,b) => a + b.val, 0);
    const s = db.items.filter(i => i.type === 'poupanca').reduce((a,b) => a + b.val, 0);
    const tot = f + p + s;
    const bal = db.income - tot;
    
    document.getElementById('topBalance').innerText = `R$ ${bal.toLocaleString('pt-BR', {minimumFractionDigits: 2})}`;
    document.getElementById('topBalance').className = `text-xl font-black ${bal < 0 ? 'text-rose-500' : 'text-emerald-500'}`;
    document.getElementById('totalFixed').innerText = `R$ ${f.toFixed(0)}`;
    document.getElementById('totalPlanned').innerText = `R$ ${p.toFixed(0)}`;
    document.getElementById('totalSavings').innerText = `R$ ${s.toFixed(0)}`;
    document.getElementById('usageBar').style.width = db.income > 0 ? `${Math.min((tot/db.income)*100, 100)}%` : '0%';
    document.getElementById('pctText').innerText = db.income > 0 ? `${((tot/db.income)*100).toFixed(0)}%` : '0%';
    
    if (db.updatedAt > 0) {
        const d = new Date(db.updatedAt);
        document.getElementById('lastUpdatedLabel').innerText = `Save: ${d.getHours()}:${d.getMinutes().toString().padStart(2, '0')}`;
    }

    const list = document.getElementById('list'); list.innerHTML = '';
    db.items.forEach(i => {
        const div = document.createElement('div'); 
        div.className = `glass p-4 rounded-3xl flex items-center justify-between border-l-4 border-${i.type==='fixo'?'indigo':i.type==='planejado'?'amber':'cyan'}-500 animate-item mb-3 shadow-lg`;
        div.innerHTML = `<div class="flex items-center gap-3 overflow-hidden">
            <button onclick="togglePaid(${i.id})" class="w-10 h-10 rounded-2xl flex items-center justify-center border transition-all ${i.paid ? 'bg-emerald-500 border-emerald-500 text-black shadow-lg shadow-emerald-500/20' : 'bg-slate-950 border-white/5 text-slate-600'}">
                <i data-lucide="${i.paid ? 'check' : 'clock'}" class="w-5 h-5"></i></button>
            <div class="overflow-hidden"><p class="text-sm font-bold truncate ${i.paid?'text-slate-500 line-through font-normal':'text-white'}">${escapeHTML(i.desc)}</p>
            <p class="text-[8px] font-black text-slate-500 uppercase">${escapeHTML(i.cat)} • ${i.date}</p></div></div>
            <div class="flex items-center gap-2"><p class="font-black text-sm">R$ ${i.val.toLocaleString('pt-BR')}</p>
            <button onclick="deleteItem(${i.id})" class="p-3 text-slate-700 hover:text-rose-500 tap-active transition-colors"><i data-lucide="trash-2" class="w-5 h-5"></i></button></div>`;
        list.appendChild(div);
    });

    const canvas = document.getElementById('chartCanvas');
    if (chartInst) { chartInst.destroy(); chartInst = null; }
    chartInst = new Chart(canvas, { 
        type: 'doughnut', 
        data: { datasets: [{ data: [f, p, s, Math.max(0, bal)], backgroundColor: ['#6366f1', '#f59e0b', '#06b6d4', '#10b981'], borderWidth: 0, cutout: '88%', borderRadius: 15 }] }, 
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, animation: { duration: 800 } } 
    });
    lucide.createIcons();
}

window.onload = async () => {
    const v = await getFromDB(); 
    if (!v) document.getElementById('authBtn').innerText = "Criar Carteira Blindada";
    lucide.createIcons();
};