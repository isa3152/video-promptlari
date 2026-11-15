/* =====================================================================
   Prompt Merkezi — script.js
   Firebase Auth + Firestore + App Check (reCAPTCHA v3)

   ÖNEMLİ: Gerçek güvenlik bu dosyada DEĞİL, Firestore Security Rules'tadır
   (firestore.rules). Bu dosya sadece arayüzü yönetir ve girdileri temizler.
   Tarayıcıdaki kod her zaman değiştirilebilir; yetkiyi sunucu denetler.
   ===================================================================== */

import { initializeApp } from "https://www.gstatic.com/firebasejs/11.0.2/firebase-app.js";
import { initializeAppCheck, ReCaptchaV3Provider } from "https://www.gstatic.com/firebasejs/11.0.2/firebase-app-check.js";
import {
  initializeAuth, indexedDBLocalPersistence, browserLocalPersistence,
  onAuthStateChanged, createUserWithEmailAndPassword, signInWithEmailAndPassword,
  signOut, sendEmailVerification, sendPasswordResetEmail, updateProfile
} from "https://www.gstatic.com/firebasejs/11.0.2/firebase-auth.js";
import {
  getFirestore, doc, getDoc, setDoc, updateDoc, collection,
  writeBatch, serverTimestamp, query, orderBy, limit, onSnapshot
} from "https://www.gstatic.com/firebasejs/11.0.2/firebase-firestore.js";

/* ---------------------------------------------------------------------
   1) AYARLAR — Firebase konsolundan aldığınız değerleri yapıştırın.
   (firebaseConfig gizli değildir; güvenliği Rules + App Check sağlar.)
   --------------------------------------------------------------------- */
const firebaseConfig = {
  apiKey: "BURAYA_API_KEY",
  authDomain: "BURAYA_PROJE.firebaseapp.com",
  projectId: "BURAYA_PROJE_ID",
  appId: "BURAYA_APP_ID"
};
const RECAPTCHA_SITE_KEY = "BURAYA_RECAPTCHA_V3_SITE_KEY";

const POST_COOLDOWN_SEC = 30;      // firestore.rules içindeki süreyle aynı olmalı
const MAX_MESSAGE = 500;
const MIN_PASSWORD = 10;
const MAX_FILE_BYTES = 700000;     // firestore.rules ile uyumlu (Firestore belge sınırı ~1 MB)

const TYPES = { prompt: "Prompt", image: "Resim", file: "Dosya", video: "Video", link: "Link" };

// Yüklenebilecek dosya türleri (uzantı → mime). Çalıştırılabilir / HTML / SVG kasıtlı olarak yok.
const FILE_TYPES = {
  pdf: "application/pdf",
  zip: "application/zip",
  txt: "text/plain",
  md: "text/markdown",
  json: "application/json",
  csv: "text/csv",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation"
};
const IMAGE_MIMES = ["image/jpeg", "image/png", "image/webp"];

/* ---------------------------------------------------------------------
   2) YARDIMCILAR: girdi temizleme / doğrulama
   --------------------------------------------------------------------- */
const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;   // her zaman textContent: HTML olarak yorumlanmaz
  return n;
}

// Kontrol karakterleri, sıfır genişlikli ve yön değiştiren (bidi) karakterler
const UNSAFE_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F​-‏‪-‮⁠-⁩﻿]/g;
// HTML'e dönüşebilecek karakterler
const ANGLE = /[<>]/g;

function sanitizeLine(value, max) {
  return String(value ?? "")
    .normalize("NFC")
    .replace(UNSAFE_CHARS, "")
    .replace(ANGLE, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

// keepAngles: prompt metinlerinde <tag> gibi ifadeler olabilir; bunlar zaten textContent ile gösterildiği için zararsızdır.
function sanitizeText(value, max, keepAngles = false) {
  let s = String(value ?? "")
    .normalize("NFC")
    .replace(/\r\n?/g, "\n")
    .replace(UNSAFE_CHARS, "");
  if (!keepAngles) s = s.replace(ANGLE, "");
  return s.replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim().slice(0, max);
}

const safeFileName = (name) => sanitizeLine(String(name ?? "").replace(/[\\/:*?"<>|]/g, "_"), 120);

const NAME_RE = /^[\p{L}\p{N} ._-]{2,24}$/u;
const EMAIL_RE = /^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']{2,}$/;
const normEmail = (v) => String(v ?? "").trim().toLowerCase();
const isEmail = (v) => v.length <= 254 && EMAIL_RE.test(v);

// Yalnızca https bağlantılara izin verir (javascript:, data: vb. reddedilir)
function safeHttps(value) {
  try {
    const u = new URL(String(value ?? "").trim());
    return u.protocol === "https:" && u.href.length <= 500 ? u.href : null;
  } catch { return null; }
}

function parseYouTubeId(value) {
  const s = String(value ?? "").trim();
  const ID = /^[A-Za-z0-9_-]{11}$/;
  if (ID.test(s)) return s;
  try {
    const u = new URL(s);
    const host = u.hostname.replace(/^(www|m)\./, "");
    let id = null;
    if (host === "youtu.be") id = u.pathname.slice(1).split("/")[0];
    else if (host === "youtube.com" || host === "youtube-nocookie.com") {
      if (u.pathname === "/watch") id = u.searchParams.get("v");
      else id = (u.pathname.match(/^\/(?:embed|shorts|live)\/([A-Za-z0-9_-]{11})/) || [])[1];
    }
    return ID.test(id || "") ? id : null;
  } catch { return null; }
}

const AUTH_ERRORS = {
  "auth/invalid-credential": "E-posta veya şifre hatalı.",
  "auth/wrong-password": "E-posta veya şifre hatalı.",
  "auth/user-not-found": "E-posta veya şifre hatalı.",
  "auth/invalid-email": "Geçersiz e-posta adresi.",
  "auth/email-already-in-use": "Bu e-posta zaten kayıtlı.",
  "auth/weak-password": "Şifre çok zayıf.",
  "auth/too-many-requests": "Çok fazla deneme yapıldı. Biraz bekleyip tekrar deneyin.",
  "auth/network-request-failed": "Ağ hatası. Bağlantınızı kontrol edin.",
  "permission-denied": "İşlem reddedildi (yetki yok, çok hızlı gönderim veya hesap kısıtlı)."
};
const friendlyError = (err) => AUTH_ERRORS[err?.code] || "Bir hata oluştu. Lütfen tekrar deneyin.";

function say(node, text, type = "") {
  node.textContent = text || "";
  node.className = "msg-line " + type;
  node.hidden = !text;
}

function flash(text, type = "") {
  const n = $("global-msg");
  n.textContent = text || "";
  n.className = "notice " + type;
  n.hidden = !text;
}

const setBusy = (form, busy) => form.querySelectorAll("button").forEach((b) => (b.disabled = busy));
const fmtDate = (d) => (d ? new Intl.DateTimeFormat("tr-TR", { dateStyle: "medium", timeStyle: "short" }).format(d) : "…");
const fmtSize = (n) => (n < 1024 ? n + " B" : n < 1048576 ? Math.round(n / 1024) + " KB" : (n / 1048576).toFixed(1) + " MB");

/* ---------------------------------------------------------------------
   3) BOT KATMANLARI (istemci tarafı — zayıf ama ucuz ilk filtre)
   Asıl koruma: App Check + Firestore Rules (rate limit, e-posta doğrulama).
   --------------------------------------------------------------------- */
const pageLoadedAt = Date.now();

function botChecks(form) {
  const trap = form.querySelector(".hp");
  if (trap && trap.value !== "") return false;                 // bal küpü dolu → bot
  if (Date.now() - pageLoadedAt < 2500) {                       // insan olmayacak kadar hızlı
    flash("Çok hızlı! Lütfen birkaç saniye bekleyin.", "warn");
    return false;
  }
  return true;
}

// Giriş denemesi sınırı (tarayıcıda; Firebase de sunucuda kendi sınırını uygular)
const LOCK_KEY = "login_guard";
function loginLockSeconds() {
  try {
    const d = JSON.parse(localStorage.getItem(LOCK_KEY) || "{}");
    return d.until && Date.now() < d.until ? Math.ceil((d.until - Date.now()) / 1000) : 0;
  } catch { return 0; }
}
function noteLoginFail() {
  try {
    const d = JSON.parse(localStorage.getItem(LOCK_KEY) || "{}");
    const count = (d.count || 0) + 1;
    localStorage.setItem(LOCK_KEY, JSON.stringify(count >= 5 ? { count: 0, until: Date.now() + 60000 } : { count }));
  } catch { /* yoksay */ }
}
const clearLoginFails = () => { try { localStorage.removeItem(LOCK_KEY); } catch { /* yoksay */ } };

/* ---------------------------------------------------------------------
   4) DURUM
   --------------------------------------------------------------------- */
let app, auth, db;
let signingUp = false;
let resendLockedUntil = 0;
let verifyTimer = null;
const blobCache = new Map();

const state = {
  user: null, profile: null, isOwner: false,
  view: "content", filterType: "all", search: "",
  messages: [], users: [], content: [],
  unsub: { messages: null, users: null, content: null }
};

const roleOf = () => (state.isOwner ? "owner" : state.profile?.role === "moderator" ? "moderator" : "user");
const isBanned = () => state.profile?.banned === true;
const canView = () => !!state.user && state.user.emailVerified && !!state.profile && !isBanned();
const canModerate = () => canView() && (state.isOwner || roleOf() === "moderator");

/* ---------------------------------------------------------------------
   5) BAŞLATMA
   --------------------------------------------------------------------- */
const notConfigured = [...Object.values(firebaseConfig), RECAPTCHA_SITE_KEY]
  .some((v) => !v || String(v).startsWith("BURAYA"));

bindStaticUi();

if (notConfigured) {
  $("boot").hidden = true;
  $("setup-warning").hidden = false;
} else {
  start();
}

function start() {
  // Yerelde (localhost) test ederken App Check hata ayıklama belirteci kullanılır.
  if (["localhost", "127.0.0.1"].includes(location.hostname)) {
    self.FIREBASE_APPCHECK_DEBUG_TOKEN = true;
  }

  app = initializeApp(firebaseConfig);
  initializeAppCheck(app, {
    provider: new ReCaptchaV3Provider(RECAPTCHA_SITE_KEY),
    isTokenAutoRefreshEnabled: true
  });
  auth = initializeAuth(app, { persistence: [indexedDBLocalPersistence, browserLocalPersistence] });
  db = getFirestore(app);

  onAuthStateChanged(auth, (user) => { if (!signingUp) loadSession(user); });
}

/* ---------------------------------------------------------------------
   6) OTURUM / PROFİL / KURUCU KONTROLÜ
   Kurucu olup olmadığınızı istemci KARAR VERMEZ: "owners/{uid}" belgesi
   yalnızca Firebase konsolundan oluşturulabilir (kurallar istemci yazımını reddeder).
   --------------------------------------------------------------------- */
async function loadSession(user) {
  stopAllWatches();
  state.user = user;
  state.profile = null;
  state.isOwner = false;
  flash("");

  if (user) {
    try {
      const ref = doc(db, "users", user.uid);
      let snap = await getDoc(ref);
      if (!snap.exists()) {
        await ensureProfile(user);
        snap = await getDoc(ref);
      }
      state.profile = snap.data();
      state.isOwner = await checkOwner(user.uid);
    } catch (err) {
      console.error(err);
      flash("Profil yüklenemedi. " + friendlyError(err), "bad");
    }
  }

  render();
  startWatches();
}

async function ensureProfile(user) {
  let name = sanitizeLine(user.displayName || (user.email || "").split("@")[0], 24);
  if (name.length < 2) name = "Üye " + user.uid.slice(0, 4);
  await setDoc(doc(db, "users", user.uid), {
    displayName: name,
    email: user.email,
    role: "user",
    banned: false,
    createdAt: serverTimestamp(),
    lastPostAt: serverTimestamp()
  });
}

async function checkOwner(uid) {
  try { return (await getDoc(doc(db, "owners", uid))).exists(); }
  catch { return false; }
}

/* ---------------------------------------------------------------------
   7) CANLI VERİ DİNLEYİCİLERİ — yalnızca erişim hakkı olan kullanıcı için açılır
   --------------------------------------------------------------------- */
function startWatches() {
  if (!canView()) return;
  subscribeMessages();
  subscribeContent();
  if (state.isOwner) startOwnerWatch();
}

function stopAllWatches() {
  for (const k of Object.keys(state.unsub)) {
    if (state.unsub[k]) { state.unsub[k](); state.unsub[k] = null; }
  }
  state.messages = []; state.users = []; state.content = [];
  blobCache.clear();
}

function watchError(label) {
  return (err) => { console.error(label, err); flash(`${label} yüklenemedi. ${friendlyError(err)}`, "bad"); };
}

function subscribeMessages() {
  const q = query(collection(db, "messages"), orderBy("createdAt", "desc"), limit(50));
  state.unsub.messages = onSnapshot(q, (snap) => {
    state.messages = snap.docs
      .map((d) => ({ id: d.id, ...d.data() }))
      .filter((m) => typeof m.text === "string" && typeof m.authorName === "string")
      .map((m) => ({ ...m, createdAt: m.createdAt?.toDate?.() || null }));
    renderMessages();
  }, watchError("Mesajlar"));
}

function subscribeContent() {
  const q = query(collection(db, "content"), orderBy("createdAt", "desc"), limit(100));
  state.unsub.content = onSnapshot(q, (snap) => {
    state.content = snap.docs
      .map((d) => ({ id: d.id, ...d.data() }))
      .filter((c) => TYPES[c.type] && typeof c.title === "string")
      .map((c) => ({ ...c, createdAt: c.createdAt?.toDate?.() || null }));
    renderContent();
  }, watchError("İçerikler"));
}

function startOwnerWatch() {
  const q = query(collection(db, "users"), orderBy("createdAt", "desc"), limit(200));
  state.unsub.users = onSnapshot(q, (snap) => {
    state.users = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
    renderUsers();
  }, watchError("Kullanıcı listesi"));
}

/* ---------------------------------------------------------------------
   8) ARAYÜZ ÇİZİMİ
   Kullanıcıdan gelen hiçbir veri innerHTML ile yazılmaz; yalnızca textContent.
   --------------------------------------------------------------------- */
function render() {
  const { user, profile } = state;
  const banned = isBanned();
  const verified = !!user?.emailVerified;
  const stage = !user ? "auth" : banned ? "banned" : !verified ? "verify" : !profile ? "loading" : "app";

  $("boot").hidden = true;
  $("screen-auth").hidden = stage !== "auth";
  $("screen-verify").hidden = stage !== "verify";
  $("screen-banned").hidden = stage !== "banned";
  $("app").hidden = stage !== "app";
  $("nav").hidden = stage !== "app";
  $("userbar").hidden = !user;

  if (user) {
    $("userbar-name").textContent = profile?.displayName || user.email || "";
    const badge = $("userbar-role");
    const role = roleOf();
    badge.className = "badge " + (banned ? "banned" : role);
    badge.textContent = banned ? "Yasaklı" : role === "owner" ? "Kurucu" : role === "moderator" ? "Moderatör" : "Üye";
  }

  $("verify-email").textContent = user?.email || "";
  if (stage === "verify") startVerifyPolling(); else stopVerifyPolling();

  $("nav-admin").hidden = !canModerate();
  $("owner-tools").hidden = !state.isOwner;
  if (state.view === "admin" && !canModerate()) state.view = "content";

  renderView();
  renderContent();
  renderMessages();
  renderUsers();
}

function setView(v) {
  if (!["content", "messages", "admin"].includes(v)) return;
  if (v === "admin" && !canModerate()) return;
  state.view = v;
  renderView();
}

function renderView() {
  for (const v of ["content", "messages", "admin"]) $("view-" + v).hidden = state.view !== v;
  document.querySelectorAll(".navbtn").forEach((b) => b.classList.toggle("active", b.dataset.view === state.view));
}

/* ---- İçerik kartları ---- */
function visibleContent() {
  const q = state.search.toLowerCase();
  return state.content.filter((c) =>
    (state.filterType === "all" || c.type === state.filterType) &&
    (!q || [c.title, c.description, c.category, c.text].some((v) => (v || "").toLowerCase().includes(q))));
}

function renderContent() {
  const list = $("content-list");
  list.replaceChildren();
  if (!canView()) return;
  const items = visibleContent();
  $("content-empty").hidden = items.length > 0;
  for (const c of items) list.append(buildContentCard(c));
}

function buildContentCard(c) {
  const li = el("li", "citem");

  const head = el("div", "chead");
  head.append(el("span", "badge type-" + c.type, TYPES[c.type]));
  if (typeof c.category === "string" && c.category) head.append(el("span", "badge cat", c.category));
  li.append(head, el("h3", "ctitle", c.title));
  if (typeof c.description === "string" && c.description) li.append(el("p", "cdesc", c.description));

  const body = el("div", "cbody");
  const actions = el("div", "cactions");

  if (c.type === "prompt" && typeof c.text === "string") {
    body.append(el("div", "prompt-text", c.text));
    const copy = el("button", "btn small", "Kopyala");
    copy.type = "button";
    copy.addEventListener("click", async () => {
      const ok = await copyText(c.text);
      copy.textContent = ok ? "Kopyalandı ✓" : "Kopyalanamadı";
      setTimeout(() => (copy.textContent = "Kopyala"), 1500);
    });
    actions.append(copy);
  }

  if (c.type === "image") {
    const show = el("button", "btn small", "Resmi göster");
    show.type = "button";
    show.addEventListener("click", async () => {
      show.disabled = true;
      show.textContent = "Yükleniyor…";
      try {
        const b64 = await fetchBlobData(c.id);
        const img = el("img", "cimg");
        img.alt = c.title;
        img.src = `data:${IMAGE_MIMES.includes(c.mime) ? c.mime : "image/jpeg"};base64,${b64}`;
        body.prepend(img);
        show.remove();
        const dl = el("button", "btn ghost small", "İndir");
        dl.type = "button";
        dl.addEventListener("click", () => downloadBase64(b64, c.fileName));
        actions.append(dl);
      } catch (err) {
        show.disabled = false;
        show.textContent = "Resmi göster";
        flash("Resim yüklenemedi. " + friendlyError(err), "bad");
      }
    });
    actions.append(show);
  }

  if (c.type === "file") {
    body.append(el("p", "muted", `${safeFileName(c.fileName)} · ${fmtSize(Number(c.size) || 0)}`));
    const dl = el("button", "btn small", "İndir");
    dl.type = "button";
    dl.addEventListener("click", async () => {
      dl.disabled = true;
      try { downloadBase64(await fetchBlobData(c.id), c.fileName); }
      catch (err) { flash("Dosya indirilemedi. " + friendlyError(err), "bad"); }
      finally { dl.disabled = false; }
    });
    actions.append(dl);
  }

  if (c.type === "video" && /^[A-Za-z0-9_-]{11}$/.test(c.videoId || "")) {
    const wrap = el("div", "video");
    const f = document.createElement("iframe");
    f.src = "https://www.youtube-nocookie.com/embed/" + c.videoId;
    f.title = c.title;
    f.loading = "lazy";
    f.allowFullscreen = true;
    f.referrerPolicy = "strict-origin-when-cross-origin";
    f.setAttribute("sandbox", "allow-scripts allow-same-origin allow-presentation");
    wrap.append(f);
    body.append(wrap);
  }

  if (c.type === "link") {
    const href = safeHttps(c.url);
    if (href) {
      body.append(el("p", "muted", new URL(href).hostname));
      const a = el("a", "btn small", "Bağlantıyı aç");
      a.href = href;
      a.target = "_blank";
      a.rel = "noopener noreferrer nofollow";
      actions.append(a);
    }
  }

  if (body.childNodes.length) li.append(body);

  const foot = el("div", "cfoot");
  foot.append(el("span", "", fmtDate(c.createdAt)));
  if (state.isOwner) {
    const del = el("button", "btn ghost small", "Sil");
    del.type = "button";
    del.addEventListener("click", () => deleteContent(c));
    foot.append(del);
  }
  if (actions.childNodes.length) li.append(actions);
  li.append(foot);
  return li;
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.append(ta);
      ta.select();
      const ok = document.execCommand("copy");
      ta.remove();
      return ok;
    } catch { return false; }
  }
}

// Ağır veri (resim/dosya) ayrı belgede tutulur; yalnızca istenince okunur → kota tasarrufu
async function fetchBlobData(id) {
  if (blobCache.has(id)) return blobCache.get(id);
  const snap = await getDoc(doc(db, "contentData", id));
  const data = snap.exists() ? snap.data().data : null;
  if (typeof data !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(data)) throw new Error("bad-data");
  blobCache.set(id, data);
  return data;
}

function downloadBase64(b64, fileName) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  // octet-stream: tarayıcı dosyayı sayfa içinde AÇMAZ, sadece indirir
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = safeFileName(fileName) || "dosya";
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

/* ---- Mesajlar ---- */
function renderMessages() {
  const list = $("messages");
  list.replaceChildren();
  if (!canView()) return;

  if (!state.messages.length) {
    list.append(el("li", "muted", "Henüz mesaj yok."));
    return;
  }

  for (const m of state.messages) {
    const li = el("li", "msg");
    const head = el("div", "msg-head");
    head.append(el("span", "msg-author", m.authorName), el("span", "", fmtDate(m.createdAt)));
    li.append(head, el("p", "msg-body", m.text));

    const mine = m.uid === state.user.uid;
    if (mine || canModerate()) {
      const actions = el("div", "msg-actions");
      const del = el("button", "btn ghost small", "Sil");
      del.type = "button";
      del.addEventListener("click", () => deleteMessage(m.id));
      actions.append(del);
      li.append(actions);
    }
    list.append(li);
  }
}

/* ---- Kullanıcı yönetimi (yalnızca Kurucu) ---- */
function renderUsers() {
  const list = $("user-list");
  list.replaceChildren();
  if (!state.isOwner || !canView()) return;

  const q = sanitizeLine($("user-search").value, 60).toLowerCase();
  const rows = state.users.filter((u) =>
    !q || (u.displayName || "").toLowerCase().includes(q) || (u.email || "").toLowerCase().includes(q));

  for (const u of rows) {
    const li = el("li", "user-row");
    const info = el("div", "user-info");
    info.append(el("div", "user-name", u.displayName || "(adsız)"), el("div", "user-mail", u.email || ""));

    const self = u.id === state.user.uid;
    const isMod = u.role === "moderator";
    const badge = el("span", "badge " + (self ? "owner" : u.banned ? "banned" : isMod ? "moderator" : ""),
      self ? "Kurucu (siz)" : u.banned ? "Yasaklı" : isMod ? "Moderatör" : "Üye");

    li.append(info, badge);

    if (!self) {
      const actions = el("div", "user-actions");
      actions.append(
        actionBtn(isMod ? "Moderatörlüğü al" : "Moderatör yap", "ghost",
          () => changeUser(u.id, { role: isMod ? "user" : "moderator" })),
        actionBtn(u.banned ? "Banı kaldır" : "Banla", u.banned ? "ghost" : "danger",
          () => changeUser(u.id, { banned: !u.banned }, u.banned ? null : `${u.displayName || "Bu kullanıcı"} banlansın mı?`))
      );
      li.append(actions);
    }
    list.append(li);
  }
}

function actionBtn(label, kind, onClick) {
  const b = el("button", "btn small " + kind, label);
  b.type = "button";
  b.addEventListener("click", onClick);
  return b;
}

/* ---------------------------------------------------------------------
   9) FIRESTORE İŞLEMLERİ (istemci yalnızca İSTER; karar Firestore Rules'ta)
   --------------------------------------------------------------------- */
async function deleteMessage(id) {
  if (!confirm("Bu mesaj silinsin mi?")) return;
  try {
    const batch = writeBatch(db);
    batch.delete(doc(db, "messages", id));
    await batch.commit();
  } catch (err) { flash(friendlyError(err), "bad"); }
}

async function deleteContent(c) {
  if (!state.isOwner || !confirm(`"${c.title}" silinsin mi?`)) return;
  try {
    const batch = writeBatch(db);
    batch.delete(doc(db, "content", c.id));
    if (c.hasData) batch.delete(doc(db, "contentData", c.id));
    await batch.commit();
  } catch (err) { flash(friendlyError(err), "bad"); }
}

async function changeUser(uid, patch, confirmText) {
  if (!state.isOwner) return;
  if (confirmText && !confirm(confirmText)) return;
  say($("admin-msg"), "");
  try { await updateDoc(doc(db, "users", uid), patch); }
  catch (err) { say($("admin-msg"), friendlyError(err), "bad"); }
}

/* ---------------------------------------------------------------------
   10) İÇERİK EKLEME (Kurucu) — resim sıkıştırma / dosya okuma
   --------------------------------------------------------------------- */
function toBase64(blob) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).split(",")[1] || "");
    r.onerror = () => reject(r.error);
    r.readAsDataURL(blob);
  });
}

// Resmi tuvalde yeniden çizip JPEG'e çevirir: boyutu küçültür ve gömülü her türlü şüpheli veriyi atar.
async function compressImage(file) {
  if (!IMAGE_MIMES.includes(file.type)) throw new Error("Resim JPG, PNG veya WEBP olmalı.");
  const bmp = await createImageBitmap(file);
  let scale = Math.min(1, 1600 / Math.max(bmp.width, bmp.height));
  let quality = 0.85;
  for (let i = 0; i < 8; i++) {
    const w = Math.max(1, Math.round(bmp.width * scale));
    const h = Math.max(1, Math.round(bmp.height * scale));
    const canvas = document.createElement("canvas");
    canvas.width = w; canvas.height = h;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#fff";
    ctx.fillRect(0, 0, w, h);
    ctx.drawImage(bmp, 0, 0, w, h);
    const blob = await new Promise((res) => canvas.toBlob(res, "image/jpeg", quality));
    if (blob && blob.size <= MAX_FILE_BYTES) return blob;
    quality = Math.max(0.5, quality - 0.1);
    scale *= 0.85;
  }
  throw new Error("Resim yeterince küçültülemedi.");
}

async function onAddContent(e) {
  e.preventDefault();
  const out = $("c-msg");
  say(out, "");
  if (!state.isOwner) return;

  const type = $("c-type").value;
  if (!TYPES[type]) return;
  const title = sanitizeLine($("c-title").value, 100);
  if (!title) return say(out, "Başlık gerekli.", "bad");

  const content = { type, title, createdAt: serverTimestamp(), createdBy: state.user.uid };
  const category = sanitizeLine($("c-category").value, 30);
  const description = sanitizeText($("c-desc").value, 500);
  if (category) content.category = category;
  if (description) content.description = description;

  let b64 = null;
  setBusy(e.target, true);
  try {
    if (type === "prompt") {
      const text = sanitizeText($("c-text").value, 8000, true);
      if (!text) throw new Error("Prompt metni boş olamaz.");
      content.text = text;
    } else if (type === "link") {
      const href = safeHttps($("c-url").value);
      if (!href) throw new Error("Geçerli bir https:// bağlantısı girin.");
      content.url = href;
    } else if (type === "video") {
      const id = parseYouTubeId($("c-video").value);
      if (!id) throw new Error("Geçerli bir YouTube bağlantısı girin.");
      content.videoId = id;
    } else {
      const file = $("c-file").files[0];
      if (!file) throw new Error("Bir dosya seçin.");
      if (type === "image") {
        const blob = await compressImage(file);
        b64 = await toBase64(blob);
        content.fileName = safeFileName(file.name.replace(/\.[^.]+$/, "")) + ".jpg";
        content.mime = "image/jpeg";
        content.size = blob.size;
      } else {
        const ext = (file.name.split(".").pop() || "").toLowerCase();
        if (!FILE_TYPES[ext]) throw new Error("İzin verilen türler: " + Object.keys(FILE_TYPES).join(", "));
        if (file.size > MAX_FILE_BYTES) throw new Error(`Dosya en fazla ${fmtSize(MAX_FILE_BYTES)} olabilir. Daha büyükler için Link türünü kullanın.`);
        b64 = await toBase64(file);
        content.fileName = safeFileName(file.name);
        content.mime = FILE_TYPES[ext];
        content.size = file.size;
      }
      if (!content.fileName) content.fileName = "dosya";
      content.hasData = true;
    }

    const ref = doc(collection(db, "content"));
    const batch = writeBatch(db);
    batch.set(ref, content);
    if (b64) batch.set(doc(db, "contentData", ref.id), { data: b64 });
    await batch.commit();

    e.target.reset();
    updateContentFields();
    say(out, "Yayınlandı.", "ok");
  } catch (err) {
    say(out, err?.code ? friendlyError(err) : (err?.message || "Bir hata oluştu."), "bad");
  } finally {
    setBusy(e.target, false);
  }
}

function updateContentFields() {
  const type = $("c-type").value;
  document.querySelectorAll("#form-content .field").forEach((f) => {
    f.hidden = !f.dataset.for.split(" ").includes(type);
  });
  $("c-file-hint").textContent = type === "image"
    ? "JPG/PNG/WEBP — otomatik küçültülür."
    : `İzin verilenler: ${Object.keys(FILE_TYPES).join(", ")} — en fazla ${fmtSize(MAX_FILE_BYTES)}.`;
}

/* ---------------------------------------------------------------------
   11) GİRİŞ / KAYIT / DOĞRULAMA / MESAJ FORMLARI
   --------------------------------------------------------------------- */
async function onLogin(e) {
  e.preventDefault();
  const out = $("auth-msg");
  say(out, "");
  if (!botChecks(e.target)) return;

  const lock = loginLockSeconds();
  if (lock > 0) return say(out, `Çok fazla hatalı deneme. ${lock} sn bekleyin.`, "warn");

  const email = normEmail($("login-email").value);
  const pass = $("login-pass").value;
  if (!isEmail(email) || pass.length < 1 || pass.length > 128) {
    return say(out, "E-posta veya şifre geçersiz.", "bad");
  }

  setBusy(e.target, true);
  try {
    await signInWithEmailAndPassword(auth, email, pass);
    clearLoginFails();
    $("login-pass").value = "";
  } catch (err) {
    noteLoginFail();
    say(out, friendlyError(err), "bad");
  } finally {
    setBusy(e.target, false);
  }
}

async function onRegister(e) {
  e.preventDefault();
  const out = $("auth-msg");
  say(out, "");
  if (!botChecks(e.target)) return;

  const name = sanitizeLine($("reg-name").value, 24);
  const email = normEmail($("reg-email").value);
  const pass = $("reg-pass").value;

  if (!NAME_RE.test(name)) return say(out, "Ad 2-24 karakter olmalı (harf, rakam, boşluk . _ -).", "bad");
  if (!isEmail(email)) return say(out, "Geçersiz e-posta adresi.", "bad");
  if (pass.length < MIN_PASSWORD || pass.length > 128) return say(out, `Şifre en az ${MIN_PASSWORD} karakter olmalı.`, "bad");

  setBusy(e.target, true);
  signingUp = true;
  try {
    const cred = await createUserWithEmailAndPassword(auth, email, pass);
    await updateProfile(cred.user, { displayName: name });
    await setDoc(doc(db, "users", cred.user.uid), {
      displayName: name,
      email: cred.user.email,
      role: "user",
      banned: false,
      createdAt: serverTimestamp(),
      lastPostAt: serverTimestamp()
    });
    await sendEmailVerification(cred.user);
    $("reg-pass").value = "";
  } catch (err) {
    say(out, friendlyError(err), "bad");
  } finally {
    signingUp = false;
    setBusy(e.target, false);
  }
  await loadSession(auth.currentUser);   // → doğrulama ekranı açılır
}

async function onReset() {
  const out = $("auth-msg");
  const email = normEmail($("login-email").value);
  if (!isEmail(email)) return say(out, "Önce e-posta adresinizi yazın.", "bad");
  try { await sendPasswordResetEmail(auth, email); } catch { /* hesap var/yok bilgisi sızdırma */ }
  say(out, "Bu e-posta kayıtlıysa sıfırlama bağlantısı gönderildi.", "ok");
}

async function onPost(e) {
  e.preventDefault();
  const out = $("post-msg");
  say(out, "");
  if (!botChecks(e.target)) return;

  const { user, profile } = state;
  if (!canView()) return;

  const text = sanitizeText($("msg-text").value, MAX_MESSAGE);
  if (!text) return say(out, "Mesaj boş olamaz.", "bad");

  const last = profile.lastPostAt?.toMillis?.() ?? 0;
  const wait = Math.ceil((last + POST_COOLDOWN_SEC * 1000 - Date.now()) / 1000);
  if (wait > 0) return say(out, `${wait} sn sonra tekrar deneyin.`, "warn");

  setBusy(e.target, true);
  try {
    // Tek toplu yazım: mesaj + lastPostAt. Kurallar ikisini birlikte doğrular (sunucu taraflı hız sınırı).
    const batch = writeBatch(db);
    batch.set(doc(collection(db, "messages")), {
      uid: user.uid,
      authorName: profile.displayName,
      text,
      createdAt: serverTimestamp()
    });
    batch.update(doc(db, "users", user.uid), { lastPostAt: serverTimestamp() });
    await batch.commit();

    $("msg-text").value = "";
    updateCounter();
    state.profile = (await getDoc(doc(db, "users", user.uid))).data();
    say(out, "Gönderildi.", "ok");
  } catch (err) {
    say(out, friendlyError(err), "bad");
  } finally {
    setBusy(e.target, false);
  }
}

/* ---- Doğrulama ekranı ---- */
async function onResend() {
  const out = $("verify-msg");
  if (Date.now() < resendLockedUntil) return say(out, "Lütfen biraz bekleyin.", "warn");
  try {
    await sendEmailVerification(state.user);
    resendLockedUntil = Date.now() + 60000;
    say(out, "Doğrulama e-postası gönderildi. Spam klasörünü de kontrol edin.", "ok");
  } catch (err) {
    say(out, friendlyError(err), "bad");
  }
}

async function checkVerified(manual = false) {
  const out = $("verify-msg");
  if (!state.user) return;
  try {
    await state.user.reload();
    if (state.user.emailVerified) {
      await state.user.getIdToken(true);   // doğrulama bilgisini yeni belirece taşır
      stopVerifyPolling();
      await loadSession(auth.currentUser);
    } else if (manual) {
      say(out, "Henüz doğrulanmamış görünüyor. Bağlantıya tıkladıktan sonra tekrar deneyin.", "warn");
    }
  } catch (err) {
    if (manual) say(out, friendlyError(err), "bad");
  }
}

// Doğrulama ekranı açıkken 6 sn'de bir otomatik kontrol (en fazla 15 dk)
function startVerifyPolling() {
  if (verifyTimer) return;
  const startedAt = Date.now();
  verifyTimer = setInterval(() => {
    if (Date.now() - startedAt > 15 * 60 * 1000) return stopVerifyPolling();
    checkVerified(false);
  }, 6000);
}
function stopVerifyPolling() {
  if (verifyTimer) { clearInterval(verifyTimer); verifyTimer = null; }
}

function updateCounter() {
  $("msg-count").textContent = `${$("msg-text").value.length}/${MAX_MESSAGE}`;
}

function showTab(which) {
  const login = which === "login";
  $("form-login").hidden = !login;
  $("form-register").hidden = login;
  $("tab-login").classList.toggle("active", login);
  $("tab-register").classList.toggle("active", !login);
  say($("auth-msg"), "");
}

function bindStaticUi() {
  $("tab-login").addEventListener("click", () => showTab("login"));
  $("tab-register").addEventListener("click", () => showTab("register"));
  $("form-login").addEventListener("submit", onLogin);
  $("form-register").addEventListener("submit", onRegister);
  $("form-post").addEventListener("submit", onPost);
  $("form-content").addEventListener("submit", onAddContent);
  $("btn-reset").addEventListener("click", onReset);
  $("btn-resend").addEventListener("click", onResend);
  $("btn-verified").addEventListener("click", () => checkVerified(true));
  const logout = () => { if (auth) signOut(auth); };
  $("btn-logout").addEventListener("click", logout);
  $("btn-verify-logout").addEventListener("click", logout);
  $("msg-text").addEventListener("input", updateCounter);
  $("user-search").addEventListener("input", renderUsers);
  $("c-type").addEventListener("change", updateContentFields);
  updateContentFields();

  document.querySelectorAll(".navbtn").forEach((b) => b.addEventListener("click", () => setView(b.dataset.view)));

  $("content-search").addEventListener("input", (e) => {
    state.search = sanitizeLine(e.target.value, 60);
    renderContent();
  });
  document.querySelectorAll(".chip").forEach((chip) => chip.addEventListener("click", () => {
    state.filterType = chip.dataset.type;
    document.querySelectorAll(".chip").forEach((c) => c.classList.toggle("active", c === chip));
    renderContent();
  }));

  // Sekmeye geri dönünce doğrulamayı hemen kontrol et
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.user && !state.user.emailVerified) checkVerified(false);
  });
}
