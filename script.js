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
  initializeAuth, indexedDBLocalPersistence, browserLocalPersistence, browserPopupRedirectResolver,
  GoogleAuthProvider, signInWithPopup,
  onAuthStateChanged, createUserWithEmailAndPassword, signInWithEmailAndPassword,
  signOut, sendEmailVerification, sendPasswordResetEmail, updateProfile
} from "https://www.gstatic.com/firebasejs/11.0.2/firebase-auth.js";
import {
  getFirestore, doc, getDoc, setDoc, updateDoc, deleteDoc, collection,
  writeBatch, serverTimestamp, query, orderBy, limit, onSnapshot
} from "https://www.gstatic.com/firebasejs/11.0.2/firebase-firestore.js";

/* ---------------------------------------------------------------------
   1) AYARLAR
   --------------------------------------------------------------------- */
const firebaseConfig = {
  apiKey: "AIzaSyDieqe3GjCgaCsvBqhSM1Fp37U7l3CQ1Co",
  authDomain: "video-promptlari.firebaseapp.com",
  projectId: "video-promptlari",
  appId: "1:698308645411:web:685df7c61d97ce7ea4d796"
};
const RECAPTCHA_SITE_KEY = "BURAYA_RECAPTCHA_V3_SITE_KEY";   // boş bırakılırsa bot koruması (App Check) kapalı kalır

const SITE_NAME = "Prompt Merkezi";   // sitenin adı (tüm ekranlarda burası kullanılır)
const PRO_CONTACT_URL = "";           // Pro için iletişim bağlantısı (https://...). Ör: Telegram, Instagram, YouTube kanalınız
const PRO_CONTACT_LABEL = "İletişime geç";

const POST_COOLDOWN_SEC = 30;      // firestore.rules içindeki süreyle aynı olmalı
const MAX_MESSAGE = 500;
const MIN_PASSWORD = 10;
const MAX_FILE_BYTES = 700000;     // firestore.rules ile uyumlu (Firestore belge sınırı ~1 MB)

const TYPES = { prompt: "Prompt", image: "Resim", file: "Dosya", video: "Video", link: "Link" };
const TYPE_ICON = { prompt: "edit", image: "image", file: "file", video: "play", link: "link" };

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

// Kütüphane sekmeleri: hangi türleri gösterir
const LIB = {
  prompts:   { title: "Promptlar", types: ["prompt"] },
  videos:    { title: "Videolar", types: ["video"] },
  resources: { title: "Kaynaklar", types: ["image", "file", "link"] },
  favorites: { title: "Favorilerim", types: null },
  search:    { title: "Arama sonuçları", types: null }
};
const VIEW_SECTION = {
  home: "home", prompts: "library", videos: "library", resources: "library", favorites: "library", search: "library",
  messages: "messages", settings: "settings", pro: "pro", admin: "admin"
};

/* ---------------------------------------------------------------------
   2) YARDIMCILAR: DOM, girdi temizleme / doğrulama
   --------------------------------------------------------------------- */
const $ = (id) => document.getElementById(id);
const SVGNS = "http://www.w3.org/2000/svg";

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;   // her zaman textContent: HTML olarak yorumlanmaz
  return n;
}

function icon(name, cls = "") {
  const s = document.createElementNS(SVGNS, "svg");
  s.setAttribute("class", ("ic " + cls).trim());
  s.setAttribute("aria-hidden", "true");
  const u = document.createElementNS(SVGNS, "use");
  u.setAttribute("href", "#i-" + name);
  s.append(u);
  return s;
}

function mkBtn(label, cls, iconName, onClick) {
  const b = el("button", "btn " + cls);
  b.type = "button";
  if (iconName) b.append(icon(iconName));
  b.append(document.createTextNode(label));
  if (onClick) b.addEventListener("click", () => onClick(b));
  return b;
}

// Kontrol karakterleri, sıfır genişlikli ve yön değiştiren (bidi) karakterler
const UNSAFE_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F​-‏‪-‮⁠-⁩﻿]/g;
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
  "auth/operation-not-allowed": "Bu giriş yöntemi Firebase'de açık değil (Authentication → Sign-in method).",
  "auth/unauthorized-domain": "Bu site adresi Firebase'de yetkilendirilmemiş (Authentication → Settings → Authorized domains).",
  "auth/invalid-api-key": "Firebase API anahtarı geçersiz. script.js içindeki apiKey değerini kontrol edin.",
  "auth/api-key-not-valid": "Firebase API anahtarı geçersiz. script.js içindeki apiKey değerini kontrol edin.",
  "auth/popup-blocked": "Açılır pencere engellendi. Tarayıcıda bu site için açılır pencerelere izin verin.",
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
  const trap = form?.querySelector(".hp");
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
let lastPostLocal = 0;
const blobCache = new Map();

const state = {
  user: null, profile: null, isOwner: false, stage: "boot",
  guest: "landing",                      // landing | login | register
  view: "home", prevView: "home", filterType: "all", search: "",
  messages: [], users: [], content: [], favs: new Set(), revealed: new Set(),
  unsub: { profile: null, messages: null, users: null, content: null, favs: null }
};

const roleOf = () => (state.isOwner ? "owner" : state.profile?.role === "moderator" ? "moderator" : "user");
const isBanned = () => state.profile?.banned === true;
const canView = () => !!state.user && state.user.emailVerified && !!state.profile && !isBanned();
const canModerate = () => canView() && (state.isOwner || roleOf() === "moderator");
const hasPro = () => canView() && (state.isOwner || state.profile?.pro === true);

/* ---------------------------------------------------------------------
   5) BAŞLATMA
   --------------------------------------------------------------------- */
// Yalnızca Firebase ayarları zorunlu. reCAPTCHA anahtarı yoksa App Check atlanır (bot koruması kapalı kalır).
const notConfigured = Object.values(firebaseConfig).some((v) => !v || String(v).startsWith("BURAYA"));
const appCheckEnabled = !!RECAPTCHA_SITE_KEY && !String(RECAPTCHA_SITE_KEY).startsWith("BURAYA");

document.title = SITE_NAME;
document.querySelectorAll(".site-name").forEach((n) => (n.textContent = SITE_NAME));
bindStaticUi();

if (notConfigured) {
  $("boot").hidden = true;
  $("setup-warning").hidden = false;
} else {
  start();
}

function start() {
  app = initializeApp(firebaseConfig);

  if (appCheckEnabled) {
    // Yerelde (localhost) test ederken App Check hata ayıklama belirteci kullanılır.
    if (["localhost", "127.0.0.1"].includes(location.hostname)) {
      self.FIREBASE_APPCHECK_DEBUG_TOKEN = true;
    }
    initializeAppCheck(app, {
      provider: new ReCaptchaV3Provider(RECAPTCHA_SITE_KEY),
      isTokenAutoRefreshEnabled: true
    });
  } else {
    console.warn("App Check kapalı: RECAPTCHA_SITE_KEY girilmedi. Bot koruması için KURULUM.md Adım 4'e bakın.");
  }

  auth = initializeAuth(app, {
    persistence: [indexedDBLocalPersistence, browserLocalPersistence],
    popupRedirectResolver: browserPopupRedirectResolver
  });
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
  state.view = "home";
  state.search = "";
  state.filterType = "all";
  $("content-search").value = "";
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
      watchProfile(user.uid);
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

// Kendi profilini canlı izle: Pro verildiğinde / ban atıldığında sayfayı yenilemeye gerek kalmaz.
function watchProfile(uid) {
  state.unsub.profile = onSnapshot(doc(db, "users", uid), (snap) => {
    if (!snap.exists() || !state.user) return;
    const was = canView();
    state.profile = snap.data();
    const now = canView();
    if (now && !was) startWatches();
    if (!now && was) stopDataWatches();
    render();
  }, (err) => console.error("profil", err));
}

/* ---------------------------------------------------------------------
   7) CANLI VERİ DİNLEYİCİLERİ — yalnızca erişim hakkı olan kullanıcı için açılır
   --------------------------------------------------------------------- */
function startWatches() {
  if (!canView() || state.unsub.content) return;
  subscribeMessages();
  subscribeContent();
  subscribeFavs();
  if (state.isOwner) startOwnerWatch();
}

function stopDataWatches() {
  for (const k of ["messages", "users", "content", "favs"]) {
    if (state.unsub[k]) { state.unsub[k](); state.unsub[k] = null; }
  }
  state.messages = []; state.users = []; state.content = []; state.favs = new Set();
  state.revealed = new Set();
  blobCache.clear();
}

function stopAllWatches() {
  stopDataWatches();
  if (state.unsub.profile) { state.unsub.profile(); state.unsub.profile = null; }
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

function subscribeFavs() {
  state.unsub.favs = onSnapshot(collection(db, "users", state.user.uid, "favorites"), (snap) => {
    state.favs = new Set(snap.docs.map((d) => d.id));
    renderContent();
  }, watchError("Favoriler"));
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
  const stage = !user ? "guest" : banned ? "banned" : !verified ? "verify" : !profile ? "loading" : "app";
  state.stage = stage;

  $("boot").hidden = stage !== "loading";
  $("btn-boot-logout").hidden = !user;
  $("screen-landing").hidden = !(stage === "guest" && state.guest === "landing");
  $("screen-auth").hidden = !(stage === "guest" && state.guest !== "landing");
  $("pane-login").hidden = state.guest !== "login";
  $("pane-register").hidden = state.guest !== "register";
  $("screen-verify").hidden = stage !== "verify";
  $("screen-banned").hidden = stage !== "banned";
  $("app").hidden = stage !== "app";

  $("verify-email").textContent = user?.email || "";
  if (stage === "verify") startVerifyPolling(); else stopVerifyPolling();

  if (stage !== "app") return;

  const name = profile.displayName || user.email || "";
  $("avatar-letter").textContent = ([...name.trim()][0] || "?").toLocaleUpperCase("tr");
  $("nav-admin").hidden = !canModerate();
  $("owner-tools").hidden = !state.isOwner;
  if (state.view === "admin" && !canModerate()) state.view = "home";

  renderShell();
  renderView();
  renderContent();
  renderMessages();
  renderUsers();
}

function renderShell() {
  const { user, profile } = state;
  const pro = hasPro();
  const role = roleOf();
  const name = profile.displayName || user.email || "";

  $("home-title").textContent = `Hoş geldin, ${name}!`;

  // Pro kutuları (kenar menü + ana sayfa)
  document.querySelectorAll(".probox").forEach((box) => {
    const text = box.querySelector(".probox-text");
    const btn = box.querySelector(".probox-btn");
    if (text) text.textContent = pro ? "Pro üyesin. Teşekkürler!" : "Daha fazla özellik için Pro'ya yükselt!";
    if (btn) btn.textContent = pro ? "Detaylar" : "Yükselt";
  });
  $("pro-banner").hidden = pro;

  // Ayarlar
  $("set-name").textContent = name;
  $("set-email").textContent = user.email || "";
  $("set-role").textContent = role === "owner" ? "Kurucu" : role === "moderator" ? "Moderatör" : "Üye";
  $("set-pro").textContent = state.isOwner ? "Kurucu (tüm içerikler açık)" : pro ? "Aktif" : "Yok";

  // Pro sayfası
  $("pro-status").textContent = pro ? "Pro üyesin ✓" : "Pro'ya yükselt";
  const href = safeHttps(PRO_CONTACT_URL);
  const contact = $("pro-contact");
  contact.hidden = !href || pro;
  if (href) { contact.href = href; contact.textContent = PRO_CONTACT_LABEL; }
  $("pro-nocontact").hidden = !!href || pro;
  $("pro-howto").hidden = pro;
}

function setView(v, clearSearch = true) {
  if (!VIEW_SECTION[v]) return;
  if (v === "admin" && !canModerate()) return;
  if (clearSearch) { state.search = ""; $("content-search").value = ""; }
  state.view = v;
  state.filterType = "all";
  renderView();
  renderContent();
  window.scrollTo({ top: 0 });
}

function renderView() {
  const sec = VIEW_SECTION[state.view] || "home";
  document.querySelectorAll(".view").forEach((v) => {
    if (v.id.startsWith("view-")) v.hidden = v.id !== "view-" + sec;
  });
  document.querySelectorAll(".navbtn").forEach((b) => b.classList.toggle("active", b.dataset.view === state.view));
  if (sec === "library") {
    $("lib-title").textContent = LIB[state.view].title;
    buildChips();
  }
  // Admin bölümünün iç kutusu .view sınıfını taşıdığı için yukarıdaki döngüde gizlenmemeli
  $("owner-tools").hidden = !state.isOwner;
}

function buildChips() {
  const types = state.view === "resources" ? ["image", "file", "link"]
    : (state.view === "favorites" || state.view === "search") ? ["prompt", "image", "file", "video", "link"] : [];
  const box = $("chips");
  box.replaceChildren();
  box.hidden = types.length === 0;
  for (const t of types.length ? ["all", ...types] : []) {
    const b = el("button", "chip" + (state.filterType === t ? " active" : ""), t === "all" ? "Tümü" : TYPES[t]);
    b.type = "button";
    b.addEventListener("click", () => { state.filterType = t; buildChips(); renderContent(); });
    box.append(b);
  }
}

/* ---- İçerik kartları ---- */
function visibleContent() {
  const cfg = LIB[state.view];
  if (!cfg) return [];
  let items = state.content;
  if (cfg.types) items = items.filter((c) => cfg.types.includes(c.type));
  if (state.view === "favorites") items = items.filter((c) => state.favs.has(c.id));
  if (state.filterType !== "all") items = items.filter((c) => c.type === state.filterType);
  const q = state.search.toLowerCase();
  if (q) items = items.filter((c) => [c.title, c.description, c.category, c.text].some((v) => (v || "").toLowerCase().includes(q)));
  return items;
}

function renderContent() {
  const home = $("home-list");
  const list = $("content-list");
  home.replaceChildren();
  list.replaceChildren();
  if (!canView()) return;

  for (const c of state.content.slice(0, 6)) home.append(buildContentCard(c));
  if (!state.content.length) home.append(el("li", "muted", "Henüz içerik eklenmemiş."));

  if (VIEW_SECTION[state.view] !== "library") return;
  const items = visibleContent();
  const empty = $("content-empty");
  empty.hidden = items.length > 0;
  empty.textContent = state.view === "favorites" ? "Henüz favori eklemedin. Kartlardaki ♥ düğmesine bas."
    : state.view === "search" ? "Sonuç bulunamadı." : "Burada henüz içerik yok.";
  for (const c of items) list.append(buildContentCard(c));
}

// Yüklenmiş (görüntülenebilir) veri var mı?
function readyPayload(c) {
  if ((c.type === "prompt" || c.type === "link") && !c.pro) return { text: c.text, url: c.url };
  if (!state.revealed.has(c.id)) return null;
  if (c.type === "video" && !c.pro) return { videoId: c.videoId };
  return blobCache.get(c.id) || null;
}

async function getPayload(c) {
  if (c.pro || c.hasData) return fetchPayload(c.id);
  return { text: c.text, url: c.url, videoId: c.videoId };
}

function buildContentCard(c) {
  const li = el("li", "citem");
  const locked = c.pro === true && !hasPro();

  const head = el("div", "chead");
  const typeBadge = el("span", "badge type");
  typeBadge.append(icon(TYPE_ICON[c.type]), document.createTextNode(TYPES[c.type]));
  head.append(typeBadge);
  if (c.pro) {
    const pb = el("span", "badge pro");
    pb.append(icon("crown"), document.createTextNode("PRO"));
    head.append(pb);
  }
  if (typeof c.category === "string" && c.category) head.append(el("span", "badge cat", c.category));
  li.append(head, el("h3", "ctitle", c.title));
  if (typeof c.description === "string" && c.description) li.append(el("p", "cdesc", c.description));

  const body = el("div", "cbody");
  const actions = el("div", "cactions");

  if (locked) {
    const box = el("div", "locked");
    box.append(icon("lock"), el("b", "", "Bu içerik Pro üyelere özel"), el("small", "", "Görmek için Pro'ya yükselt."));
    body.append(box);
    actions.append(mkBtn("Pro'ya yükselt", "small", "crown", () => setView("pro")));
  } else if (c.type === "file") {
    body.append(el("p", "muted", `${safeFileName(c.fileName)} · ${fmtSize(Number(c.size) || 0)}`));
    actions.append(mkBtn("İndir", "small", "download", async (b) => {
      b.disabled = true;
      try { const p = await getPayload(c); downloadBase64(p.data, c.fileName); }
      catch (err) { flash("Dosya indirilemedi. " + friendlyError(err), "bad"); }
      finally { b.disabled = false; }
    }));
  } else {
    const p = readyPayload(c);
    if (p) mountPayload(c, body, actions, p);
    else if (c.type === "video") body.append(revealButton(c));
    else actions.append(revealButton(c));
  }

  if (body.childNodes.length) li.append(body);
  if (actions.childNodes.length) li.append(actions);

  const foot = el("div", "cfoot");
  foot.append(el("span", "", fmtDate(c.createdAt)));
  const right = el("div", "row");
  const fav = state.favs.has(c.id);
  const favBtn = mkBtn(fav ? "Favoride" : "Favori", "ghost small" + (fav ? " on" : ""), "heart", () => toggleFav(c.id));
  favBtn.setAttribute("aria-pressed", String(fav));
  right.append(favBtn);
  if (state.isOwner) right.append(mkBtn("Sil", "ghost small", "trash", () => deleteContent(c)));
  foot.append(right);
  li.append(foot);
  return li;
}

function revealButton(c) {
  const labels = { prompt: "Promptu göster", image: "Resmi göster", video: "Videoyu oynat", link: "Bağlantıyı göster" };
  const label = labels[c.type] || "Göster";
  const onClick = async (b) => {
    b.disabled = true;
    try {
      await getPayload(c);
      state.revealed.add(c.id);
      renderContent();
    } catch (err) {
      b.disabled = false;
      flash("İçerik yüklenemedi. " + friendlyError(err), "bad");
    }
  };
  if (c.type === "video") {
    const f = el("button", "facade");
    f.type = "button";
    f.append(icon("play"), el("span", "", label));
    f.addEventListener("click", () => onClick(f));
    return f;
  }
  return mkBtn(label, "small", TYPE_ICON[c.type], onClick);
}

function mountPayload(c, body, actions, p) {
  if (c.type === "prompt" && typeof p.text === "string") {
    body.append(el("div", "prompt-text", p.text));
    actions.append(mkBtn("Kopyala", "small", "copy", async (b) => {
      const ok = await copyText(p.text);
      b.replaceChildren(icon(ok ? "check" : "copy"), document.createTextNode(ok ? "Kopyalandı" : "Kopyalanamadı"));
      setTimeout(() => b.replaceChildren(icon("copy"), document.createTextNode("Kopyala")), 1500);
    }));
  } else if (c.type === "image" && typeof p.data === "string") {
    const img = el("img", "cimg");
    img.alt = c.title;
    img.src = `data:${IMAGE_MIMES.includes(c.mime) ? c.mime : "image/jpeg"};base64,${p.data}`;
    body.append(img);
    actions.append(mkBtn("İndir", "small ghost", "download", () => downloadBase64(p.data, c.fileName)));
  } else if (c.type === "video" && /^[A-Za-z0-9_-]{11}$/.test(p.videoId || "")) {
    const wrap = el("div", "video");
    const f = document.createElement("iframe");
    f.src = "https://www.youtube-nocookie.com/embed/" + p.videoId;
    f.title = c.title;
    f.loading = "lazy";
    f.allowFullscreen = true;
    f.referrerPolicy = "strict-origin-when-cross-origin";
    f.setAttribute("sandbox", "allow-scripts allow-same-origin allow-presentation");
    wrap.append(f);
    body.append(wrap);
  } else if (c.type === "link") {
    const href = safeHttps(p.url);
    if (href) {
      body.append(el("p", "muted", new URL(href).hostname));
      const a = el("a", "btn small");
      a.append(icon("external"), document.createTextNode("Bağlantıyı aç"));
      a.href = href;
      a.target = "_blank";
      a.rel = "noopener noreferrer nofollow";
      actions.append(a);
    }
  }
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

// Ağır / Pro veri ayrı belgede tutulur; yalnızca istenince okunur → kota tasarrufu ve sunucu taraflı Pro kilidi.
async function fetchPayload(id) {
  if (blobCache.has(id)) return blobCache.get(id);
  const snap = await getDoc(doc(db, "contentData", id));
  if (!snap.exists()) throw new Error("bad-data");
  const d = snap.data();
  const out = {};
  if (typeof d.data === "string" && /^[A-Za-z0-9+/]+={0,2}$/.test(d.data)) out.data = d.data;
  if (typeof d.text === "string") out.text = d.text.slice(0, 8000);
  if (typeof d.url === "string") out.url = d.url;
  if (typeof d.videoId === "string" && /^[A-Za-z0-9_-]{11}$/.test(d.videoId)) out.videoId = d.videoId;
  blobCache.set(id, out);
  return out;
}

function downloadBase64(b64, fileName) {
  if (typeof b64 !== "string") throw new Error("bad-data");
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
      actions.append(mkBtn("Sil", "ghost small", "trash", () => deleteMessage(m.id)));
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
    const badges = el("div", "user-badges");
    badges.append(el("span", "badge " + (self ? "owner" : u.banned ? "banned" : isMod ? "moderator" : ""),
      self ? "Kurucu (siz)" : u.banned ? "Yasaklı" : isMod ? "Moderatör" : "Üye"));
    if (u.pro === true) {
      const pb = el("span", "badge pro");
      pb.append(icon("crown"), document.createTextNode("PRO"));
      badges.append(pb);
    }
    li.append(info, badges);

    if (!self) {
      const actions = el("div", "user-actions");
      actions.append(
        mkBtn(u.pro === true ? "Pro'yu al" : "Pro yap", u.pro === true ? "ghost small" : "small", "crown",
          () => changeUser(u.id, { pro: u.pro !== true })),
        mkBtn(isMod ? "Moderatörlüğü al" : "Moderatör yap", "ghost small", null,
          () => changeUser(u.id, { role: isMod ? "user" : "moderator" })),
        mkBtn(u.banned ? "Banı kaldır" : "Banla", u.banned ? "ghost small" : "danger small", null,
          () => changeUser(u.id, { banned: !u.banned }, u.banned ? null : `${u.displayName || "Bu kullanıcı"} banlansın mı?`))
      );
      li.append(actions);
    }
    list.append(li);
  }
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
    if (c.hasData || c.pro) batch.delete(doc(db, "contentData", c.id));
    await batch.commit();
    blobCache.delete(c.id);
  } catch (err) { flash(friendlyError(err), "bad"); }
}

async function toggleFav(id) {
  if (!canView()) return;
  const ref = doc(db, "users", state.user.uid, "favorites", id);
  try {
    if (state.favs.has(id)) await deleteDoc(ref);
    else await setDoc(ref, { createdAt: serverTimestamp() });
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

  const pro = $("c-pro").checked;
  const content = { type, title, createdAt: serverTimestamp(), createdBy: state.user.uid };
  if (pro) content.pro = true;
  const category = sanitizeLine($("c-category").value, 30);
  const description = sanitizeText($("c-desc").value, 500);
  if (category) content.category = category;
  if (description) content.description = description;

  // Pro içeriğin asıl verisi ayrı belgeye (contentData) yazılır; kurallar onu yalnızca Pro üyelere açar.
  let payload = null;
  setBusy(e.target, true);
  try {
    if (type === "prompt") {
      const text = sanitizeText($("c-text").value, 8000, true);
      if (!text) throw new Error("Prompt metni boş olamaz.");
      if (pro) payload = { text }; else content.text = text;
    } else if (type === "link") {
      const href = safeHttps($("c-url").value);
      if (!href) throw new Error("Geçerli bir https:// bağlantısı girin.");
      if (pro) payload = { url: href }; else content.url = href;
    } else if (type === "video") {
      const id = parseYouTubeId($("c-video").value);
      if (!id) throw new Error("Geçerli bir YouTube bağlantısı girin.");
      if (pro) payload = { videoId: id }; else content.videoId = id;
    } else {
      const file = $("c-file").files[0];
      if (!file) throw new Error("Bir dosya seçin.");
      let b64;
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
      payload = { data: b64 };
    }

    const ref = doc(collection(db, "content"));
    const batch = writeBatch(db);
    batch.set(ref, content);
    if (payload) batch.set(doc(db, "contentData", ref.id), payload);
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
function goGuest(which) {
  state.guest = ["login", "register"].includes(which) ? which : "landing";
  say($("auth-msg"), "");
  render();
  window.scrollTo({ top: 0 });
}

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
  if (pass !== $("reg-pass2").value) return say(out, "Şifreler aynı değil.", "bad");

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
    $("reg-pass2").value = "";
  } catch (err) {
    say(out, friendlyError(err), "bad");
  } finally {
    signingUp = false;
    setBusy(e.target, false);
  }
  await loadSession(auth.currentUser);   // → doğrulama ekranı açılır
}

async function onGoogle() {
  const out = $("auth-msg");
  say(out, "");
  if (!botChecks(null)) return;
  try {
    await signInWithPopup(auth, new GoogleAuthProvider());
  } catch (err) {
    if (["auth/popup-closed-by-user", "auth/cancelled-popup-request"].includes(err?.code)) return;
    say(out, friendlyError(err), "bad");
  }
}

async function onReset() {
  const out = $("auth-msg");
  const email = normEmail($("login-email").value);
  if (!isEmail(email)) return say(out, "Önce e-posta adresinizi yazın.", "bad");
  try { await sendPasswordResetEmail(auth, email); } catch { /* hesap var/yok bilgisi sızdırma */ }
  say(out, "Bu e-posta kayıtlıysa sıfırlama bağlantısı gönderildi.", "ok");
}

async function onSettingsReset() {
  const out = $("set-msg");
  if (!state.user?.email) return;
  try { await sendPasswordResetEmail(auth, state.user.email); } catch { /* yoksay */ }
  say(out, "Şifre sıfırlama bağlantısı e-postana gönderildi (Google ile girdiysen gerekmez).", "ok");
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

  const last = Math.max(profile.lastPostAt?.toMillis?.() ?? 0, lastPostLocal);
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

    lastPostLocal = Date.now();
    $("msg-text").value = "";
    updateCounter();
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

function onSearchInput(e) {
  state.search = sanitizeLine(e.target.value, 60);
  if (state.search && VIEW_SECTION[state.view] !== "library") {
    state.prevView = state.view;
    setView("search", false);
  } else if (!state.search && state.view === "search") {
    setView(state.prevView || "home", false);
  } else {
    renderContent();
  }
}

function bindStaticUi() {
  // Ziyaretçi ekranları
  document.querySelectorAll("[data-go]").forEach((b) => b.addEventListener("click", () => goGuest(b.dataset.go)));
  document.querySelectorAll("[data-scroll]").forEach((b) => b.addEventListener("click", () => {
    const t = $(b.dataset.scroll);
    if (t) t.scrollIntoView({ behavior: "smooth", block: "start" });
  }));
  document.querySelectorAll("[data-toggle]").forEach((b) => b.addEventListener("click", () => {
    const input = $(b.dataset.toggle);
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    b.replaceChildren(icon(show ? "eyeoff" : "eye"));
  }));

  $("form-login").addEventListener("submit", onLogin);
  $("form-register").addEventListener("submit", onRegister);
  $("btn-reset").addEventListener("click", onReset);
  $("btn-google-login").addEventListener("click", onGoogle);
  $("btn-google-register").addEventListener("click", onGoogle);

  // Doğrulama
  $("btn-resend").addEventListener("click", onResend);
  $("btn-verified").addEventListener("click", () => checkVerified(true));

  // Çıkış düğmeleri
  const logout = () => { if (auth) signOut(auth); };
  for (const id of ["btn-boot-logout", "btn-verify-logout", "btn-banned-logout", "btn-set-logout"]) $(id).addEventListener("click", logout);

  // Panel gezinmesi (kenar menü, kartlar, Pro düğmeleri)
  document.querySelectorAll("[data-view]").forEach((b) => b.addEventListener("click", () => setView(b.dataset.view)));
  $("btn-avatar").addEventListener("click", () => setView("settings"));
  $("content-search").addEventListener("input", onSearchInput);

  // Mesajlar / ayarlar / yönetim
  $("form-post").addEventListener("submit", onPost);
  $("msg-text").addEventListener("input", updateCounter);
  $("btn-set-reset").addEventListener("click", onSettingsReset);
  $("form-content").addEventListener("submit", onAddContent);
  $("c-type").addEventListener("change", updateContentFields);
  $("user-search").addEventListener("input", renderUsers);
  updateContentFields();

  // Sekmeye geri dönünce doğrulamayı hemen kontrol et
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.user && !state.user.emailVerified) checkVerified(false);
  });
}
