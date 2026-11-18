// 암호화된 파일(d/…)을 받아서 브라우저 안에서 풀어 app/… 주소로 보여 주는 서비스워커
const BASE = new URL("./", self.location).pathname;
const APP = BASE + "app/";
const MIME = { html: "text/html; charset=utf-8", js: "text/javascript; charset=utf-8", mjs: "text/javascript; charset=utf-8",
  css: "text/css; charset=utf-8", json: "application/json", txt: "text/plain; charset=utf-8", jpg: "image/jpeg", jpeg: "image/jpeg",
  png: "image/png", gif: "image/gif", webp: "image/webp", svg: "image/svg+xml", pdf: "application/pdf", ttf: "font/ttf",
  otf: "font/otf", woff: "font/woff", woff2: "font/woff2" };
let keysP = null;

function idb() {
  return new Promise((ok, no) => { const r = indexedDB.open("kuksi", 1); r.onupgradeneeded = () => r.result.createObjectStore("k"); r.onsuccess = () => ok(r.result); r.onerror = () => no(r.error); });
}
async function idbDo(mode, fn) {
  const db = await idb();
  return new Promise((ok, no) => { const t = db.transaction("k", mode); const q = fn(t.objectStore("k")); t.oncomplete = () => ok(q && q.result); t.onerror = () => no(t.error); });
}
async function loadKeys() {
  const raw = await idbDo("readonly", s => s.get("k"));
  if (!raw) return null;
  const b = new Uint8Array(raw);
  return {
    enc: await crypto.subtle.importKey("raw", b.slice(0, 32), "AES-GCM", false, ["decrypt"]),
    name: await crypto.subtle.importKey("raw", b.slice(32, 64), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
  };
}
const getKeys = () => keysP || (keysP = loadKeys().catch(() => null));
const hex = buf => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, "0")).join("");

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", e => e.waitUntil(self.clients.claim()));
self.addEventListener("message", e => { if (e.data === "reset") keysP = null; });

self.addEventListener("fetch", e => {
  const u = new URL(e.request.url);
  if (u.origin !== self.location.origin || !u.pathname.startsWith(APP) || e.request.method !== "GET") return;
  e.respondWith(serve(e.request, u));
});

function toLogin(req, rel) {
  if (req.mode === "navigate") return Response.redirect(BASE + "?next=" + encodeURIComponent(rel), 302);
  return new Response("로그인이 필요해요", { status: 401 });
}

async function serve(req, u) {
  let rel = decodeURIComponent(u.pathname.slice(APP.length)).normalize("NFC");
  if (rel === "" || rel.endsWith("/")) rel += "index.html";
  const k = await getKeys();
  if (!k) return toLogin(req, rel);
  const name = hex(await crypto.subtle.sign("HMAC", k.name, new TextEncoder().encode("p:" + rel))).slice(0, 40);
  const r = await fetch(BASE + "d/" + name);
  if (!r.ok) return new Response("없는 파일: " + rel, { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" } });
  const buf = await r.arrayBuffer();
  let pt;
  try { pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(0, 12) }, k.enc, buf.slice(12)); }
  catch (err) {  // 열쇠가 바뀜 -> 다시 로그인
    await idbDo("readwrite", s => s.delete("k")); keysP = null;
    return toLogin(req, rel);
  }
  const ext = rel.split(".").pop().toLowerCase();
  return new Response(pt, { headers: { "Content-Type": MIME[ext] || "application/octet-stream", "Cache-Control": "no-store" } });
}
