import React, { useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, Lock, Key, Plus, Search, Eye, EyeOff, Copy, Trash2, Download, Upload, LogOut, Settings, RefreshCw, Check, Info, Globe, BookOpen } from "lucide-react";

/**
 * Shiny Password Vault – Single‑file React App
 * -------------------------------------------------
 * Tech & Design:
 * - TailwindCSS utility classes for modern, shiny UI
 * - framer-motion for smooth micro-interactions
 * - lucide-react icons
 * - No backend required; uses WebCrypto + localStorage
 * - AES‑GCM encryption with PBKDF2-derived key from a Master Password
 * - Features: Landing (security tips), Auth (create/open vault), Vault (CRUD),
 *   generator, search/sort, tags, copy-to-clipboard, reveal, auto-lock,
 *   import/export (encrypted), change master password, idle timeout
 *
 * SECURITY NOTE (Important):
 * - This is a client-side demo. In production, add:
 *   • Server-side sync with end-to-end encryption
 *   • CSP, secure headers, HTTPS, Subresource Integrity
 *   • Clipboard hygiene, screen overlay prevention, anti-shoulder-surfing options
 *   • Key stretching (high PBKDF2 iterations), hardware keystore, WebAuthn
 *   • Audit logging & user revocation, encrypted backups
 */

// -------------------------- Utility: Crypto --------------------------
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

async function deriveKey(masterPassword, saltBytes, iterations = 200_000) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(masterPassword),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function toB64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function fromB64(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function encryptJSON(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = textEncoder.encode(JSON.stringify(data));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return { iv: toB64(iv), ct: toB64(ciphertext) };
}

async function decryptJSON(key, { iv, ct }) {
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(iv) }, key, fromB64(ct));
  return JSON.parse(textDecoder.decode(plaintext));
}

// -------------------------- Utility: Helpers --------------------------
function classNames(...xs) {
  return xs.filter(Boolean).join(" ");
}

function randFrom(chars) {
  const idx = Math.floor(Math.random() * chars.length);
  return chars[idx];
}

function generatePassword({ length = 16, upper = true, lower = true, digits = true, symbols = true }) {
  const U = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // removed confusing I/O
  const L = "abcdefghijkmnopqrstuvwxyz"; // removed l
  const D = "23456789"; // removed 0/1
  const S = "!@#$%^&*()_+{}[]|:;<>,.?/~";
  let pool = "";
  if (upper) pool += U;
  if (lower) pool += L;
  if (digits) pool += D;
  if (symbols) pool += S;
  if (!pool) pool = L + D;
  let out = "";
  // Ensure at least one of each selected type
  const req = [];
  if (upper) req.push(randFrom(U));
  if (lower) req.push(randFrom(L));
  if (digits) req.push(randFrom(D));
  if (symbols) req.push(randFrom(S));
  for (let i = 0; i < length - req.length; i++) out += randFrom(pool);
  out += req.join("");
  return out
    .split("")
    .sort(() => Math.random() - 0.5)
    .join("");
}

function zxcvbnishScore(pw) {
  // Lightweight heuristic: length + diversity
  if (!pw) return 0;
  const len = Math.min(24, pw.length);
  const sets = [/[A-Z]/, /[a-z]/, /\d/, /[^A-Za-z0-9]/].reduce((s, r) => s + (r.test(pw) ? 1 : 0), 0);
  return Math.min(4, Math.floor((len / 6) + sets - 1)); // 0..4
}

function StrengthBar({ value }) {
  const labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];
  const pct = ((value + 1) / 5) * 100;
  return (
    <div className="mt-2">
      <div className="w-full h-2 bg-gray-200 rounded-full overflow-hidden">
        <div className="h-2 rounded-full" style={{ width: `${pct}%` }} />
      </div>
      <div className="text-xs mt-1 text-gray-600">{labels[value] || labels[0]}</div>
    </div>
  );
}

// -------------------------- Persistent Storage --------------------------
const LS = {
  SALT: "spv.salt",
  ITER: "spv.iter",
  VAULT: "spv.vault",
  LOCK_AT: "spv.lockAt",
};

function getOrCreateSalt() {
  let b64 = localStorage.getItem(LS.SALT);
  if (b64) return fromB64(b64);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  localStorage.setItem(LS.SALT, toB64(salt));
  return salt.buffer;
}

function getIterations() {
  const v = Number(localStorage.getItem(LS.ITER));
  return Number.isFinite(v) && v > 0 ? v : 200_000;
}

// -------------------------- App --------------------------
export default function App() {
  const [page, setPage] = useState("landing");
  const [unlocked, setUnlocked] = useState(false);
  const [keyRef, setKeyRef] = useState(null); // CryptoKey
  const [vault, setVault] = useState({ items: [], updatedAt: null, version: 1 });
  const [masterHint, setMasterHint] = useState(localStorage.getItem("spv.hint") || "");
  const [idleMinutes, setIdleMinutes] = useState(10);
  const idleTimer = useRef(null);

  // Auto-lock handling
  useEffect(() => {
    const resetTimer = () => {
      if (!unlocked) return;
      if (idleTimer.current) clearTimeout(idleTimer.current);
      idleTimer.current = setTimeout(() => handleLock(), idleMinutes * 60 * 1000);
    };
    const events = ["mousemove", "keydown", "click", "scroll", "visibilitychange"];    
    events.forEach(e => window.addEventListener(e, resetTimer));
    resetTimer();
    return () => events.forEach(e => window.removeEventListener(e, resetTimer));
  }, [unlocked, idleMinutes]);

  // Load encrypted vault from storage on mount
  useEffect(() => {
    // no-op here; decrypt happens after auth
  }, []);

  function heroCard({ icon, title, text }) {
    const Icon = icon;
    return (
      <motion.div
        whileHover={{ y: -4 }}
        className="p-6 rounded-2xl bg-white/70 backdrop-blur shadow-lg border border-gray-100"
      >
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-gray-900 text-white"><Icon size={20} /></div>
          <h3 className="font-semibold text-lg">{title}</h3>
        </div>
        <p className="mt-3 text-gray-700 leading-relaxed">{text}</p>
      </motion.div>
    );
  }

  async function handleCreateOrOpen(masterPassword) {
    const salt = getOrCreateSalt();
    const iterations = getIterations();
    const key = await deriveKey(masterPassword, new Uint8Array(salt), iterations);

    const enc = localStorage.getItem(LS.VAULT);
    if (!enc) {
      // Create new empty vault
      const fresh = { items: [], updatedAt: new Date().toISOString(), version: 1 };
      const encrypted = await encryptJSON(key, fresh);
      localStorage.setItem(LS.VAULT, JSON.stringify(encrypted));
      setVault(fresh);
      setKeyRef(key);
      setUnlocked(true);
      setPage("vault");
      return { created: true };
    }

    try {
      const parsed = JSON.parse(enc);
      const data = await decryptJSON(key, parsed);
      setVault(data);
      setKeyRef(key);
      setUnlocked(true);
      setPage("vault");
      return { created: false };
    } catch (e) {
      throw new Error("Invalid master password or corrupted data");
    }
  }

  async function persistVault(next) {
    if (!keyRef) return;
    const encrypted = await encryptJSON(keyRef, next);
    localStorage.setItem(LS.VAULT, JSON.stringify(encrypted));
  }

  async function addItem(item) {
    const next = { ...vault, items: [...vault.items, { id: crypto.randomUUID(), ...item }], updatedAt: new Date().toISOString() };
    setVault(next);
    await persistVault(next);
  }

  async function updateItem(id, patch) {
    const next = { ...vault, items: vault.items.map(it => (it.id === id ? { ...it, ...patch } : it)), updatedAt: new Date().toISOString() };
    setVault(next);
    await persistVault(next);
  }

  async function removeItem(id) {
    const next = { ...vault, items: vault.items.filter(it => it.id !== id), updatedAt: new Date().toISOString() };
    setVault(next);
    await persistVault(next);
  }

  function handleLock() {
    setUnlocked(false);
    setKeyRef(null);
    setPage("auth");
  }

  async function changeMasterPassword(oldPass, newPass) {
    // Re-encrypt with new key
    const salt = getOrCreateSalt();
    const iterations = getIterations();
    const oldKey = await deriveKey(oldPass, new Uint8Array(salt), iterations);
    const enc = JSON.parse(localStorage.getItem(LS.VAULT) || "{}");
    try {
      await decryptJSON(oldKey, enc); // verify old password
    } catch (e) {
      throw new Error("Old master password incorrect");
    }
    const newKey = await deriveKey(newPass, new Uint8Array(salt), iterations);
    const encrypted = await encryptJSON(newKey, vault);
    localStorage.setItem(LS.VAULT, JSON.stringify(encrypted));
    setKeyRef(newKey);
  }

  async function exportEncrypted() {
    const enc = localStorage.getItem(LS.VAULT);
    const blob = new Blob([enc || ""], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `vault_encrypted_${new Date().toISOString().slice(0,10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  async function importEncrypted(file) {
    const text = await file.text();
    try {
      const parsed = JSON.parse(text);
      // Test decrypt with current key
      if (!keyRef) throw new Error("Unlock your vault first");
      const data = await decryptJSON(keyRef, parsed);
      setVault(data);
      localStorage.setItem(LS.VAULT, JSON.stringify(parsed));
    } catch (e) {
      alert("Failed to import: " + e.message);
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 via-white to-gray-100 text-gray-900">
      <TopNav page={page} setPage={setPage} unlocked={unlocked} onLock={handleLock} />
      <main className="max-w-6xl mx-auto px-4 py-8">
        <AnimatePresence mode="wait">
          {page === "landing" && (
            <motion.section
              key="landing"
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -12 }}
              className=""
            >
              <Hero setPage={setPage} />
              <div className="grid md:grid-cols-3 gap-6 mt-10">
                {heroCard({ icon: Shield, title: "Zero-Knowledge", text: "Your vault is encrypted locally with AES‑GCM using a key derived from your master password. We never see your secrets." })}
                {heroCard({ icon: Lock, title: "Modern Crypto", text: "PBKDF2‑SHA256 with high iterations derives a strong key; random IVs per record; import/export stays encrypted." })}
                {heroCard({ icon: Key, title: "Convenient & Powerful", text: "Password generator, strength meter, tags, search, and one‑click copy make everyday use delightful." })}
              </div>
              <CyberTips />
            </motion.section>
          )}

          {page === "auth" && (
            <motion.section key="auth" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }}>
              <AuthPanel onSubmit={handleCreateOrOpen} masterHint={masterHint} setMasterHint={setMasterHint} />
            </motion.section>
          )}

          {page === "vault" && (
            <motion.section key="vault" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }}>
              <VaultPanel
                vault={vault}
                addItem={addItem}
                updateItem={updateItem}
                removeItem={removeItem}
                onExport={exportEncrypted}
                onImport={importEncrypted}
              />
            </motion.section>
          )}

          {page === "settings" && (
            <motion.section key="settings" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }}>
              <SettingsPanel
                masterHint={masterHint}
                setMasterHint={(v) => { setMasterHint(v); localStorage.setItem("spv.hint", v); }}
                idleMinutes={idleMinutes}
                setIdleMinutes={setIdleMinutes}
                onChangeMaster={changeMasterPassword}
              />
            </motion.section>
          )}

          {page === "about" && (
            <motion.section key="about" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }}>
              <About />
            </motion.section>
          )}
        </AnimatePresence>
      </main>
      <Footer />
    </div>
  );
}

// -------------------------- UI: Nav, Hero, Footer --------------------------
function TopNav({ page, setPage, unlocked, onLock }) {
  const tabs = [
    { id: "landing", label: "Home", icon: Shield },
    { id: "auth", label: "Vault Access", icon: Lock },
    { id: "vault", label: "Vault", icon: Key },
    { id: "settings", label: "Settings", icon: Settings },
    { id: "about", label: "About", icon: Info },
  ];
  return (
    <header className="sticky top-0 z-40 bg-white/80 backdrop-blur border-b border-gray-200">
      <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-4">
        <div className="flex items-center gap-2 font-semibold">
          <div className="p-2 rounded-xl bg-gray-900 text-white"><Shield size={18} /></div>
          Password Vault
        </div>
        <nav className="ml-auto hidden md:flex items-center gap-2">
          {tabs.map(t => (
            <button key={t.id} onClick={() => setPage(t.id)} className={classNames(
              "px-3 py-2 rounded-xl text-sm flex items-center gap-2",
              page === t.id ? "bg-gray-900 text-white" : "hover:bg-gray-100"
            )}>
              <t.icon size={16} /> {t.label}
            </button>
          ))}
          {unlocked && (
            <button onClick={onLock} className="px-3 py-2 rounded-xl text-sm flex items-center gap-2 hover:bg-gray-100">
              <LogOut size={16} /> Lock
            </button>
          )}
        </nav>
      </div>
    </header>
  );
}

function Hero({ setPage }) {
  return (
    <section className="mt-8">
      <div className="grid md:grid-cols-2 gap-8 items-center">
        <div>
          <motion.h1
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-4xl md:text-5xl font-extrabold tracking-tight"
          >
            A simple, modern password manager — fully client‑side.
          </motion.h1>
          <p className="mt-4 text-gray-700 text-lg">
            Create your encrypted vault, store credentials, generate strong passwords, and keep control.
            Your master password never leaves your device.
          </p>
          <div className="mt-6 flex gap-3">
            <button onClick={() => setPage("auth")} className="px-5 py-3 rounded-2xl bg-gray-900 text-white shadow hover:shadow-md">
              Create / Unlock Vault
            </button>
            <button onClick={() => setPage("about")} className="px-5 py-3 rounded-2xl border border-gray-300 hover:bg-gray-50">
              Learn more
            </button>
          </div>
        </div>
        <div>
          <motion.div initial={{ opacity: 0, scale: 0.96 }} animate={{ opacity: 1, scale: 1 }} className="rounded-3xl border border-gray-200 shadow-lg p-6 bg-white/70 backdrop-blur">
            <div className="grid grid-cols-2 gap-4">
              {["Zero‑knowledge", "AES‑GCM 256", "PBKDF2", "Local‑first", "Tags", "Search"].map((t, i) => (
                <div key={t} className="p-4 rounded-2xl bg-gray-50 border border-gray-100 text-center text-sm font-medium">{t}</div>
              ))}
            </div>
            <p className="text-xs text-gray-600 mt-4">
              Demo app for educational purposes. For production, integrate with a backend and adopt a rigorous security model.
            </p>
          </motion.div>
        </div>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="mt-16 border-t border-gray-200">
      <div className="max-w-6xl mx-auto px-4 py-8 text-sm text-gray-600 flex flex-wrap items-center justify-between gap-3">
        <div>© {new Date().getFullYear()} Shiny Password Vault</div>
        <div className="flex items-center gap-4">
          <a className="hover:underline" href="#" onClick={(e)=>e.preventDefault()}>Security</a>
          <a className="hover:underline" href="#" onClick={(e)=>e.preventDefault()}>Privacy</a>
          <a className="hover:underline" href="#" onClick={(e)=>e.preventDefault()}>Terms</a>
        </div>
      </div>
    </footer>
  );
}

// -------------------------- Landing: Cyber Tips --------------------------
function CyberTips() {
  const tips = [
    { title: "Use a strong master password", text: "A long passphrase (16+ chars) beats complexity gimmicks. Avoid reuse." },
    { title: "Enable 2FA everywhere", text: "Use TOTP or hardware keys for critical accounts (email, banking, cloud)." },
    { title: "Beware of phishing", text: "Always verify the URL and TLS lock icon before entering credentials." },
    { title: "Keep software up to date", text: "Patch browsers, OS, and extensions to close known vulnerabilities." },
    { title: "Lock your device", text: "Auto-lock your vault and your screen when away from keyboard." },
    { title: "Back up securely", text: "Export your encrypted vault and store it offline in a safe place." },
  ];
  return (
    <section className="mt-12">
      <h2 className="text-2xl font-bold">Cybersecurity Instructions</h2>
      <p className="text-gray-700 mt-2">Quick reminders to stay safe online.</p>
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5 mt-6">
        {tips.map((t) => (
          <div key={t.title} className="p-5 rounded-2xl border border-gray-200 bg-white shadow-sm">
            <div className="font-semibold">{t.title}</div>
            <p className="text-sm text-gray-700 mt-2">{t.text}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

// -------------------------- Auth Panel --------------------------
function AuthPanel({ onSubmit, masterHint, setMasterHint }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [status, setStatus] = useState(null);
  const [mode, setMode] = useState("open"); // "open" | "create"

  async function handle() {
    setStatus(null);
    try {
      if (mode === "create" && password !== confirm) throw new Error("Master passwords do not match");
      const res = await onSubmit(password);
      setStatus({ ok: true, msg: res.created ? "Vault created" : "Vault unlocked" });
      setPassword("");
      setConfirm("");
    } catch (e) {
      setStatus({ ok: false, msg: e.message });
    }
  }

  const strength = useMemo(() => zxcvbnishScore(password), [password]);

  return (
    <div className="max-w-lg mx-auto">
      <div className="p-6 rounded-3xl border border-gray-200 bg-white shadow-lg">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-bold">{mode === "create" ? "Create Vault" : "Unlock Vault"}</h2>
          <button onClick={() => setMode(mode === "create" ? "open" : "create")} className="text-sm px-3 py-1 rounded-xl border hover:bg-gray-50">
            {mode === "create" ? "Have a vault? Unlock" : "New here? Create vault"}
          </button>
        </div>
        <div className="mt-4 space-y-4">
          <div>
            <label className="text-sm font-medium">Master Password</label>
            <input type="password" className="mt-1 w-full px-4 py-3 rounded-2xl border focus:outline-none focus:ring-2 focus:ring-gray-900" value={password} onChange={(e)=>setPassword(e.target.value)} placeholder="Enter master password" />
            <StrengthBar value={strength} />
          </div>
          {mode === "create" && (
            <div>
              <label className="text-sm font-medium">Confirm Password</label>
              <input type="password" className="mt-1 w-full px-4 py-3 rounded-2xl border focus:outline-none focus:ring-2 focus:ring-gray-900" value={confirm} onChange={(e)=>setConfirm(e.target.value)} placeholder="Re-enter master password" />
              <div className="text-xs text-gray-600 mt-2">Optional hint (visible on unlock screen)</div>
              <input type="text" className="mt-1 w-full px-4 py-2 rounded-2xl border focus:outline-none focus:ring-2 focus:ring-gray-900" value={masterHint} onChange={(e)=>setMasterHint(e.target.value)} placeholder="E.g., 'my favorite song lyric'" />
            </div>
          )}
          <button onClick={handle} className="w-full py-3 rounded-2xl bg-gray-900 text-white flex items-center justify-center gap-2">
            <Lock size={18} /> {mode === "create" ? "Create & Unlock" : "Unlock"}
          </button>
          {masterHint && mode === "open" && (
            <div className="text-xs text-gray-600">Hint: {masterHint}</div>
          )}
          {status && (
            <div className={classNames("text-sm p-3 rounded-xl", status.ok ? "bg-green-50 text-green-800" : "bg-red-50 text-red-800")}>
              {status.msg}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// -------------------------- Vault Panel --------------------------
function VaultPanel({ vault, addItem, updateItem, removeItem, onExport, onImport }) {
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState("site");
  const [desc, setDesc] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [revealIds, setRevealIds] = useState({});

  const fileRef = useRef(null);

  const items = useMemo(() => {
    let v = vault.items || [];
    if (query.trim()) {
      const q = query.toLowerCase();
      v = v.filter(it => [it.site, it.username, it.url, it.tags?.join(" "), it.notes].filter(Boolean).some(x => x.toLowerCase().includes(q)));
    }
    v = [...v].sort((a, b) => {
      const A = (a[sort] || "").toString().toLowerCase();
      const B = (b[sort] || "").toString().toLowerCase();
      return desc ? B.localeCompare(A) : A.localeCompare(B);
    });
    return v;
  }, [vault.items, query, sort, desc]);

  function toggleReveal(id) {
    setRevealIds(prev => ({ ...prev, [id]: !prev[id] }));
  }

  return (
    <div>
      <div className="flex flex-col md:flex-row md:items-center gap-3 md:gap-4">
        <div className="flex-1 flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2" size={18} />
            <input value={query} onChange={(e)=>setQuery(e.target.value)} placeholder="Search by site, username, tag…" className="w-full pl-10 pr-3 py-3 rounded-2xl border focus:outline-none focus:ring-2 focus:ring-gray-900" />
          </div>
          <button onClick={()=>setShowNew(true)} className="px-4 py-3 rounded-2xl bg-gray-900 text-white flex items-center gap-2"><Plus size={18}/> New</button>
        </div>
        <div className="flex items-center gap-2">
          <select className="px-3 py-3 rounded-2xl border" value={sort} onChange={(e)=>setSort(e.target.value)}>
            <option value="site">Sort: Site</option>
            <option value="username">Sort: Username</option>
            <option value="tags">Sort: Tags</option>
          </select>
          <button onClick={()=>setDesc(!desc)} className="px-3 py-3 rounded-2xl border flex items-center gap-2"><RefreshCw size={16}/> {desc?"Desc":"Asc"}</button>
          <button onClick={onExport} className="px-3 py-3 rounded-2xl border flex items-center gap-2"><Download size={16}/> Export</button>
          <button onClick={()=>fileRef.current?.click()} className="px-3 py-3 rounded-2xl border flex items-center gap-2"><Upload size={16}/> Import</button>
          <input ref={fileRef} type="file" accept="application/json" className="hidden" onChange={(e)=>{const f=e.target.files?.[0]; if (f) onImport(f); e.target.value="";}} />
        </div>
      </div>

      <div className="mt-6 grid gap-4">
        {items.length === 0 && (
          <div className="p-6 rounded-2xl border bg-white text-gray-600 text-sm">No entries yet. Click <strong>New</strong> to add your first item.</div>
        )}
        {items.map((it) => (
          <div key={it.id} className="p-5 rounded-2xl border bg-white shadow-sm">
            <div className="flex flex-col md:flex-row md:items-center gap-3 justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-gray-900 text-white"><Globe size={16}/></div>
                <div>
                  <div className="font-semibold">{it.site}</div>
                  <div className="text-sm text-gray-600">{it.username}</div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => navigator.clipboard.writeText(it.password)} className="px-3 py-2 rounded-xl border flex items-center gap-2 text-sm"><Copy size={16}/> Copy</button>
                <button onClick={() => toggleReveal(it.id)} className="px-3 py-2 rounded-xl border flex items-center gap-2 text-sm">{revealIds[it.id] ? <EyeOff size={16}/> : <Eye size={16}/>} {revealIds[it.id] ? "Hide" : "Reveal"}</button>
                <button onClick={() => removeItem(it.id)} className="px-3 py-2 rounded-xl border text-red-600 flex items-center gap-2 text-sm"><Trash2 size={16}/> Delete</button>
              </div>
            </div>
            <div className="grid md:grid-cols-2 gap-4 mt-4 text-sm">
              <div><span className="text-gray-500">URL:</span> <a href={it.url || "#"} target="_blank" rel="noreferrer" className="hover:underline">{it.url || "—"}</a></div>
              <div><span className="text-gray-500">Password:</span> <code className="ml-1">{revealIds[it.id] ? it.password : "•".repeat(Math.min(10, it.password?.length || 8))}</code></div>
              <div><span className="text-gray-500">Tags:</span> <span className="ml-1">{it.tags?.length ? it.tags.map(t => (<span key={t} className="px-2 py-1 rounded-lg bg-gray-100 border text-xs mr-1">#{t}</span>)) : "—"}</span></div>
              <div><span className="text-gray-500">Notes:</span> <span className="ml-1">{it.notes || "—"}</span></div>
            </div>
          </div>
        ))}
      </div>

      <AnimatePresence>
        {showNew && (
          <Modal onClose={()=>setShowNew(false)}>
            <NewItemForm onSave={async (vals)=>{await addItem(vals); setShowNew(false);}} />
          </Modal>
        )}
      </AnimatePresence>
    </div>
  );
}

function Modal({ children, onClose }) {
  useEffect(() => {
    function onKey(e){ if (e.key === "Escape") onClose(); }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-50 bg-black/30 backdrop-blur-sm flex items-center justify-center p-4">
      <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 10, opacity: 0 }} className="w-full max-w-lg p-6 rounded-3xl border bg-white shadow-xl">
        <div className="flex justify-end"><button onClick={onClose} className="px-3 py-1 rounded-xl border">Close</button></div>
        {children}
      </motion.div>
    </motion.div>
  );
}

function NewItemForm({ onSave }) {
  const [site, setSite] = useState("");
  const [username, setUsername] = useState("");
  const [url, setUrl] = useState("");
  const [password, setPassword] = useState("");
  const [tags, setTags] = useState("");
  const [notes, setNotes] = useState("");
  const [genOpen, setGenOpen] = useState(false);

  const strength = useMemo(() => zxcvbnishScore(password), [password]);

  function applyGenerated(pw) {
    setPassword(pw);
    setGenOpen(false);
  }

  return (
    <div>
      <h3 className="text-lg font-bold mb-4">Add New Entry</h3>
      <div className="grid gap-3">
        <Input label="Site / App" value={site} setValue={setSite} placeholder="e.g., Gmail" />
        <Input label="Username / Email" value={username} setValue={setUsername} placeholder="name@example.com" />
        <Input label="URL" value={url} setValue={setUrl} placeholder="https://accounts.google.com" />
        <div>
          <label className="text-sm font-medium">Password</label>
          <div className="flex gap-2 mt-1">
            <input value={password} onChange={(e)=>setPassword(e.target.value)} type="text" className="flex-1 px-4 py-3 rounded-2xl border focus:outline-none focus:ring-2 focus:ring-gray-900" placeholder="Enter or generate" />
            <button onClick={()=>setGenOpen(true)} className="px-4 py-3 rounded-2xl border">Generate</button>
          </div>
          <StrengthBar value={strength} />
        </div>
        <Input label="Tags (comma-separated)" value={tags} setValue={setTags} placeholder="work, email" />
        <div>
          <label className="text-sm font-medium">Notes</label>
          <textarea value={notes} onChange={(e)=>setNotes(e.target.value)} className="mt-1 w-full px-4 py-3 rounded-2xl border focus:outline-none focus:ring-2 focus:ring-gray-900" rows={3} placeholder="Optional" />
        </div>
        <div className="flex justify-end gap-2 mt-2">
          <button onClick={()=>onSave({ site, username, url, password, tags: tags.split(",").map(t=>t.trim()).filter(Boolean), notes })} className="px-5 py-3 rounded-2xl bg-gray-900 text-white flex items-center gap-2"><Check size={16}/> Save</button>
        </div>
      </div>

      <AnimatePresence>
        {genOpen && (
          <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} className="mt-4 p-4 rounded-2xl border bg-gray-50">
            <PasswordGenerator onUse={applyGenerated} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function Input({ label, value, setValue, placeholder }) {
  return (
    <div>
      <label className="text-sm font-medium">{label}</label>
      <input value={value} onChange={(e)=>setValue(e.target.value)} className="mt-1 w-full px-4 py-3 rounded-2xl border focus:outline-none focus:ring-2 focus:ring-gray-900" placeholder={placeholder} />
    </div>
  );
}

function PasswordGenerator({ onUse }) {
  const [length, setLength] = useState(16);
  const [upper, setUpper] = useState(true);
  const [lower, setLower] = useState(true);
  const [digits, setDigits] = useState(true);
  const [symbols, setSymbols] = useState(true);

  const pw = useMemo(() => generatePassword({ length, upper, lower, digits, symbols }), [length, upper, lower, digits, symbols]);

  return (
    <div>
      <div className="grid grid-cols-2 gap-3 text-sm">
        <label className="flex items-center gap-2">Length
          <input type="number" min={8} max={64} value={length} onChange={(e)=>setLength(Number(e.target.value))} className="ml-auto w-24 px-3 py-2 rounded-xl border" />
        </label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={upper} onChange={(e)=>setUpper(e.target.checked)} /> Uppercase</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={lower} onChange={(e)=>setLower(e.target.checked)} /> Lowercase</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={digits} onChange={(e)=>setDigits(e.target.checked)} /> Digits</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={symbols} onChange={(e)=>setSymbols(e.target.checked)} /> Symbols</label>
      </div>
      <div className="mt-3 p-3 rounded-xl bg-white border font-mono text-sm break-all">{pw}</div>
      <div className="flex items-center justify-end gap-2 mt-3">
        <button onClick={()=>navigator.clipboard.writeText(pw)} className="px-3 py-2 rounded-xl border flex items-center gap-2"><Copy size={16}/> Copy</button>
        <button onClick={()=>onUse(pw)} className="px-3 py-2 rounded-xl bg-gray-900 text-white">Use</button>
      </div>
    </div>
  );
}

// -------------------------- Settings --------------------------
function SettingsPanel({ masterHint, setMasterHint, idleMinutes, setIdleMinutes, onChangeMaster }) {
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [msg, setMsg] = useState(null);

  async function change() {
    setMsg(null);
    try {
      if (newPw !== confirm) throw new Error("New passwords do not match");
      await onChangeMaster(oldPw, newPw);
      setMsg({ ok: true, text: "Master password updated" });
      setOldPw("");
      setNewPw("");
      setConfirm("");
    } catch (e) {
      setMsg({ ok: false, text: e.message });
    }
  }

  return (
    <div className="grid md:grid-cols-2 gap-6">
      <div className="p-6 rounded-2xl border bg-white shadow-sm">
        <h3 className="font-semibold">Security & Session</h3>
        <div className="mt-4 grid gap-3 text-sm">
          <label className="flex items-center justify-between">Auto-lock idle (minutes)
            <input type="number" min={1} max={120} value={idleMinutes} onChange={(e)=>setIdleMinutes(Number(e.target.value))} className="w-28 px-3 py-2 rounded-xl border" />
          </label>
          <label className="text-sm">Master hint
            <input type="text" value={masterHint} onChange={(e)=>setMasterHint(e.target.value)} className="mt-1 w-full px-3 py-2 rounded-xl border" placeholder="Optional hint" />
          </label>
        </div>
      </div>
      <div className="p-6 rounded-2xl border bg-white shadow-sm">
        <h3 className="font-semibold">Change Master Password</h3>
        <div className="mt-4 grid gap-3 text-sm">
          <input type="password" value={oldPw} onChange={(e)=>setOldPw(e.target.value)} placeholder="Old master password" className="px-3 py-2 rounded-xl border" />
          <input type="password" value={newPw} onChange={(e)=>setNewPw(e.target.value)} placeholder="New master password" className="px-3 py-2 rounded-xl border" />
          <input type="password" value={confirm} onChange={(e)=>setConfirm(e.target.value)} placeholder="Confirm new password" className="px-3 py-2 rounded-xl border" />
          <button onClick={change} className="px-4 py-2 rounded-xl bg-gray-900 text-white w-max">Update</button>
          {msg && (
            <div className={classNames("mt-2 p-2 rounded-xl text-sm", msg.ok ? "bg-green-50 text-green-800" : "bg-red-50 text-red-800")}>{msg.text}</div>
          )}
        </div>
      </div>
    </div>
  );
}

// -------------------------- About --------------------------
function About() {
  return (
    <div className="max-w-3xl">
      <h2 className="text-2xl font-bold">About This Project</h2>
      <p className="mt-3 text-gray-700">
        This single‑file React app demonstrates a modern, local‑first password manager. It stores an encrypted vault in your browser's localStorage, using
        <strong> AES‑GCM‑256</strong> with keys derived from your master password via <strong>PBKDF2‑SHA256</strong>.
      </p>
      <ul className="list-disc ml-6 mt-3 text-gray-700">
        <li>Landing page with core cybersecurity instructions</li>
        <li>Create/Unlock vault, no account required</li>
        <li>Add credentials with tags, notes, and links</li>
        <li>Search, sort, copy, reveal/hide, password generator & strength meter</li>
        <li>Encrypted import/export and auto‑lock on idle</li>
        <li>Settings to change master password and hint</li>
      </ul>
      <div className="mt-4 p-4 rounded-2xl border bg-yellow-50 text-yellow-900 text-sm">
        <strong>Disclaimer:</strong> Educational sample only. For production, implement backend sync, 2FA/WebAuthn, threat modeling, secure headers, and independent security review.
      </div>
      <div className="mt-6 p-4 rounded-2xl border bg-white">
        <h3 className="font-semibold mb-2">Keyboard Shortcuts</h3>
        <ul className="text-sm text-gray-700 list-disc ml-6">
          <li><kbd>Esc</kbd> — close dialogs</li>
        </ul>
      </div>
      <div className="mt-6 p-4 rounded-2xl border bg-white">
        <h3 className="font-semibold mb-2">Planned Enhancements</h3>
        <ul className="text-sm text-gray-700 list-disc ml-6">
          <li>Optional cloud backup with end‑to‑end encryption</li>
          <li>Organization/team vaults with role‑based sharing</li>
          <li>Browser extension for auto‑fill</li>
          <li>Hardware key support via WebAuthn</li>
        </ul>
      </div>
    </div>
  );
}
