// groupchat – szyfrowany czat P2P (WebRTC + sygnalizacja przez Nostr, Trystero)
import {joinRoom, getRelaySockets} from 'trystero'

const APP = 'groupchat-p2p.v1'
const MAX_MEDIA = 50 * 1024 * 1024        // maks. wysyłany plik (po kompresji)
const MAX_RX = 64 * 1024 * 1024           // maks. odbierany plik
const COMPRESS_OVER = 8 * 1024 * 1024     // filmiki większe – kompresujemy
const MAX_VIDEO_S = 30
const te = new TextEncoder(), td = new TextDecoder()

// ───────────────────────── narzędzia
const $ = s => document.querySelector(s)
function h(tag, props, ...kids) {
  const el = document.createElement(tag)
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue
    if (k === 'class') el.className = v
    else if (k === 'text') el.textContent = v
    else if (k === 'style') el.style.cssText = v
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v)
    else if (k in el && typeof v !== 'string') el[k] = v
    else el.setAttribute(k, v === true ? '' : v)
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)))
  }
  return el
}
const rnd = n => crypto.getRandomValues(new Uint8Array(n))
const hex = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('')
const b64 = buf => {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf); let s = ''
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000))
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
const unb64 = s => {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='
  return Uint8Array.from(atob(s), c => c.charCodeAt(0))
}
const toU8 = x => x instanceof Uint8Array ? x : x instanceof ArrayBuffer ? new Uint8Array(x)
  : ArrayBuffer.isView(x) ? new Uint8Array(x.buffer, x.byteOffset, x.byteLength) : new Uint8Array(0)
const cleanNick = s => String(s || '').replace(/[\u0000-\u001f]/g, '').trim().slice(0, 32) || 'Bez nicku'
const cleanNum = s => /^\d{1,10}$/.test(String(s)) ? String(s) : null
const randNum = () => String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000))
const hhmm = ts => new Date(ts).toLocaleTimeString('pl-PL', {hour: '2-digit', minute: '2-digit'})
const hue = s => { let x = 0; for (const c of String(s)) x = (x * 31 + c.charCodeAt(0)) >>> 0; return x % 360 }
const avatar = (name, seed, big) => h('div', {class: 'av' + (big ? ' big' : ''), style: `background:hsl(${hue(seed)} 55% 62%)`}, (name || '?').trim().charAt(0).toUpperCase() || '?')
const sleep = ms => new Promise(r => setTimeout(r, ms))
const mb = n => (n / 1048576).toFixed(1).replace('.', ',')

let toastT
function toast(msg, ms = 3200) {
  const t = $('#toast'); t.textContent = msg; t.classList.remove('hidden')
  clearTimeout(toastT); toastT = setTimeout(() => t.classList.add('hidden'), ms)
}

// Kod weryfikacyjny osoby (z jej klucza publicznego) – 8 znaków
const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
const kodCache = new Map()
async function kodOf(uid) {
  if (kodCache.has(uid)) return kodCache.get(uid)
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode('gc-kod|' + uid)))
  let s = ''; let acc = 0, bits = 0
  for (const byte of d) { acc = (acc << 8) | byte; bits += 8; while (bits >= 5 && s.length < 8) { s += B32[(acc >> (bits - 5)) & 31]; bits -= 5 } if (s.length >= 8) break }
  const k = s.slice(0, 4) + '-' + s.slice(4, 8); kodCache.set(uid, k); return k
}
const normKod = k => String(k || '').toUpperCase().replace(/[^0-9A-Z]/g, '')

// ───────────────────────── szyfrowanie (AES-256-GCM, klucz z HKDF sekretu grupy)
async function groupKey(gid, secret) {
  const base = await crypto.subtle.importKey('raw', unb64(secret), 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-256', salt: te.encode('groupchat-v1'), info: te.encode(gid)},
    base, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt'])
}
async function encJ(key, obj) {
  const iv = rnd(12)
  const ct = await crypto.subtle.encrypt({name: 'AES-GCM', iv}, key, te.encode(JSON.stringify(obj)))
  return b64(iv) + '.' + b64(ct)
}
async function decJ(key, s) {
  const [a, b] = String(s).split('.')
  return JSON.parse(td.decode(await crypto.subtle.decrypt({name: 'AES-GCM', iv: unb64(a)}, key, unb64(b))))
}
async function encB(key, buf) {
  const iv = rnd(12), ct = new Uint8Array(await crypto.subtle.encrypt({name: 'AES-GCM', iv}, key, buf))
  const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12); return out
}
async function decB(key, data) {
  const u = toU8(data)
  return crypto.subtle.decrypt({name: 'AES-GCM', iv: u.slice(0, 12)}, key, u.slice(12))
}

// ───────────────────────── dane lokalne (bez treści wiadomości!)
const LS = 'gc.v1'
let DB = null
function normDB(x) {
  x = x && typeof x === 'object' ? x : {}
  x.me ??= null; x.contacts ??= {}; x.groups ??= {}; x.settings ??= {}; x.outbox ??= []
  return x
}
try { DB = JSON.parse(localStorage.getItem(LS)) } catch {}
DB = normDB(DB)

// ═════════════════════════ PIN APLIKACJI
// Z PIN-em wszystkie dane na telefonie (ustawienia, kontakty, kody, historia, zdjęcia) są szyfrowane
// kluczem DK, który jest zapisany wyłącznie w postaci zaszyfrowanej PIN-em (PBKDF2-SHA256, 600 000 iteracji).
const LOCK_LS = 'gc.lock', ENC_LS = 'gc.v1.enc', PIN_ITER = 600000
let dbKey = null, dkRaw = null, saveT = null
const lockInfo = () => { try { return JSON.parse(localStorage.getItem(LOCK_LS)) } catch { return null } }
function save() {
  if (dbKey) { clearTimeout(saveT); saveT = setTimeout(saveEnc, 120); return }
  if (lockInfo()) return   // zablokowane – nic nie zapisujemy jawnie
  try { localStorage.setItem(LS, JSON.stringify(DB)) } catch {}
}
async function saveEnc() { try { localStorage.setItem(ENC_LS, await encJ(dbKey, DB)) } catch {} }
async function pinKek(pin, salt) {
  const pw = await crypto.subtle.importKey('raw', te.encode(String(pin)), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey({name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PIN_ITER}, pw, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt'])
}
async function keysFromDK(dk) {
  const base = await crypto.subtle.importKey('raw', dk, 'HKDF', false, ['deriveKey'])
  const mk = info => crypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-256', salt: te.encode('groupchat-pin-v1'), info: te.encode(info)}, base, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt'])
  return {db: await mk('db'), hist: await mk('hist')}
}
async function wrapDK(pin, wipe) {
  const salt = rnd(16), kek = await pinKek(pin, salt)
  localStorage.setItem(LOCK_LS, JSON.stringify({salt: b64(salt), w: await encJ(kek, {dk: b64(dkRaw)}), wipe: !!wipe, fails: 0}))
}
async function migrateHist(oldK, newK) {
  try {
    const db = await idb(); const rows = await reqP(db.transaction('msgs').objectStore('msgs').getAll())
    for (const row of rows) {
      try {
        const m = await decJ(oldK, row.data); row.data = await encJ(newK, m)
        if (row.bin) row.bin = await encB(newK, await decB(oldK, row.bin))
        await reqP(db.transaction('msgs', 'readwrite').objectStore('msgs').put(row))
      } catch {}
    }
  } catch {}
}
async function enablePin(pin, wipe) {
  if (dkRaw) { await wrapDK(pin, wipe); return }       // zmiana PIN-u
  dkRaw = rnd(32); const k = await keysFromDK(dkRaw)
  await migrateHist(await devKey(), k.hist)
  try { const db = await idb(); await reqP(db.transaction('keys', 'readwrite').objectStore('keys').delete('dev')) } catch {}
  devKeyP = Promise.resolve(k.hist); dbKey = k.db
  await wrapDK(pin, wipe); await saveEnc(); localStorage.removeItem(LS)
}
async function disablePin() {
  const old = await devKey()
  const nk = await crypto.subtle.generateKey({name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt'])
  try { const db = await idb(); await reqP(db.transaction('keys', 'readwrite').objectStore('keys').put(nk, 'dev')) } catch {}
  await migrateHist(old, nk); devKeyP = Promise.resolve(nk)
  dbKey = null; dkRaw = null
  localStorage.removeItem(LOCK_LS); localStorage.removeItem(ENC_LS); save()
}
async function unlockPin(pin) {
  const L = lockInfo(); if (!L) return true
  try {
    const kek = await pinKek(pin, unb64(L.salt)); const {dk} = await decJ(kek, L.w)
    dkRaw = unb64(dk); const k = await keysFromDK(dkRaw)
    DB = normDB(await decJ(k.db, localStorage.getItem(ENC_LS)))
    dbKey = k.db; devKeyP = Promise.resolve(k.hist)
    L.fails = 0; localStorage.setItem(LOCK_LS, JSON.stringify(L))
    return true
  } catch {
    L.fails = (L.fails || 0) + 1; localStorage.setItem(LOCK_LS, JSON.stringify(L))
    if (L.wipe && L.fails >= 10) await wipeAll()
    return false
  }
}
async function wipeAll() {
  for (const k of [LS, ENC_LS, LOCK_LS]) try { localStorage.removeItem(k) } catch {}
  try { (await indexedDB.databases?.() || []).forEach(d => d.name && indexedDB.deleteDatabase(d.name)) } catch {}
  try { indexedDB.deleteDatabase('groupchat-hist') } catch {}
  location.hash = ''; location.reload()
}

// Serwery TURN: z ustawień telefonu, a jeśli brak – wbudowane w aplikację (BUILTIN_ICE)
// Dane wbudowanego serwera są zaszyfrowane w kodzie (nie widać ich w źródle ani na GitHubie);
// odszyfrowanie następuje dopiero w pamięci telefonu przy starcie.
let BUILTIN_ICE = []
async function loadBuiltinIce() {
  try {
    const e = typeof __ICE_ENC__ !== 'undefined' ? __ICE_ENC__ : null; if (!e?.c) return
    const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(APP + '|' + e.s)))
    const part = unb64(e.k).map((b, i) => b ^ salt[i])
    const key = await crypto.subtle.importKey('raw', part, 'AES-GCM', false, ['decrypt'])
    const list = JSON.parse(td.decode(await crypto.subtle.decrypt({name: 'AES-GCM', iv: unb64(e.i)}, key, unb64(e.c))))
    if (Array.isArray(list)) BUILTIN_ICE = list
  } catch {}
}
function iceServers() {
  if (Array.isArray(DB.settings.ice) && DB.settings.ice.length) return DB.settings.ice
  if (DB.settings.turn) {   // stary format
    const t = {urls: DB.settings.turn.split(/[\s,]+/).filter(Boolean)}
    if (DB.settings.turnUser) t.username = DB.settings.turnUser
    if (DB.settings.turnPass) t.credential = DB.settings.turnPass
    return [t]
  }
  return BUILTIN_ICE
}
function cfg(password) {
  const c = {appId: APP, password, identity: 'local'}
  const relays = String(DB.settings.relays || '').split(/[\s,]+/).filter(Boolean)
  if (relays.length) c.relayConfig = {urls: relays}
  const ice = iceServers()
  if (ice.length) c.turnConfig = ice
  return c
}
// Wklejona konfiguracja z panelu Metered / ExpressTURN / innego (JSON albo kod JS)
function parseIce(text) {
  // obsługa fragmentu przetłumaczonego przez Chrome (polskie klucze, cudzysłowy „ ” “)
  text = String(text || '').replace(/[„”“‟″]/g, '"').replace(/[‚‘’]/g, "'")
    .replace(/adresy\s*url|adres\s*url/gi, 'urls').replace(/nazwa\s*u[żz]ytkownika/gi, 'username').replace(/po[śs]wiadczenie|has[łl]o/gi, 'credential').trim()
  if (!text) return []
  const clean = list => list.map(x => ({urls: [].concat(x.urls || x.url || []).filter(u => /^turns?:/i.test(u)), username: x.username || undefined, credential: x.credential || x.password || undefined}))
    .filter(x => x.urls.length)
  try { let j = JSON.parse(text); if (!Array.isArray(j)) j = j.iceServers || [j]; const out = clean(j); if (out.length) return out } catch {}
  // kod JS: wyciągnij po kolei bloki { urls..., username..., credential... }
  const blocks = text.split(/\}\s*,?/).map(b => {
    const urls = [...b.matchAll(/turns?:[^\s"'`,\]\}]+/gi)].map(m => m[0])
    const user = (/username["']?\s*[:=]\s*["'`]([^"'`]+)/i.exec(b) || [])[1]
    const cred = (/(?:credential|password)["']?\s*[:=]\s*["'`]([^"'`]+)/i.exec(b) || [])[1]
    return {urls, username: user, credential: cred}
  }).filter(b => b.urls.length)
  if (blocks.length) return clean(blocks)
  const urls = [...text.matchAll(/turns?:[^\s"'`,\]\}]+/gi)].map(m => m[0])
  return urls.length ? [{urls: [...new Set(urls)]}] : []
}
// Sprawdza, czy serwer TURN przydziela adres przekaźnika
async function testIce(ice) {
  let pc
  try { pc = new RTCPeerConnection({iceServers: ice, iceTransportPolicy: 'relay'}) } catch { return false }
  pc.createDataChannel('t')
  return new Promise(async res => {
    const t = setTimeout(() => { pc.close(); res(false) }, 12000)
    pc.onicecandidate = e => { if (e.candidate && (e.candidate.type === 'relay' || / relay /.test(e.candidate.candidate))) { clearTimeout(t); pc.close(); res(true) } }
    try { await pc.setLocalDescription(await pc.createOffer()) } catch { clearTimeout(t); pc.close(); res(false) }
  })
}
// Czy sieć w ogóle przepuszcza UDP/STUN (wykrycie publicznego adresu)
async function testStun() {
  const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:stun.l.google.com:19302'}, {urls: 'stun:stun.cloudflare.com:3478'}]})
  pc.createDataChannel('t')
  return new Promise(async res => {
    const t = setTimeout(() => { pc.close(); res(false) }, 8000)
    pc.onicecandidate = e => { if (e.candidate && (e.candidate.type === 'srflx' || / srflx /.test(e.candidate.candidate))) { clearTimeout(t); pc.close(); res(true) } }
    try { await pc.setLocalDescription(await pc.createOffer()) } catch { clearTimeout(t); pc.close(); res(false) }
  })
}
let turnHintShown = false, relayHintAt = 0, connProblem = null
function watchErrors(room) {
  room.onError(e => {
    if (e.code === 'peer-connect-failed' && !connProblem) {
      connProblem = e.turnConfigured ? 'turn' : 'noturn'
      renderHome()
      if (!turnHintShown) { turnHintShown = true; toast(e.turnConfigured ? 'Połączenie nie wyszło mimo serwera TURN – sprawdź go w „Napraw połączenie”.' : 'Sieć blokuje bezpośrednie połączenie. Ustaw serwer TURN – na ekranie głównym „Napraw połączenie”.', 7000) }
    } else if (e.code === 'relay-failed' && Date.now() - relayHintAt > 60000) {
      relayHintAt = Date.now(); toast('Problem z połączeniem z serwerami sygnalizacji – sprawdź internet.')
    }
  })
}

// ───────────────────────── powiadomienia
let unreadTotal = 0
function notify(title, body) {
  if (!document.hidden) return
  try { navigator.vibrate?.([120, 60, 120]) } catch {}
  if (!('Notification' in window) || Notification.permission !== 'granted') return
  const opts = {body, tag: 'gc', icon: 'icon-192.png', renotify: true}
  navigator.serviceWorker?.getRegistration().then(reg => reg ? reg.showNotification(title, opts) : new Notification(title, opts))
    .catch(() => { try { new Notification(title, opts) } catch {} })
}
function updateTitle() {
  unreadTotal = [...G.values()].reduce((a, r) => a + r.unread, 0)
  document.title = unreadTotal ? `(${unreadTotal}) groupchat` : 'groupchat'
}

// ═════════════════════════ SKRZYNKA – „numer” każdej osoby
// Pokój 'num-<numer>' – właściciel numeru ogłasza się każdemu, kto wejdzie.
// Prośby o kontakt, zaproszenia do grup i połączenia idą bezpośrednio (WebRTC/DTLS)
// do zweryfikowanego klucza właściciela.
const inboxRoomId = n => 'num-' + n
const inboxPass = n => 'gc-num|' + n
const inboxActions = room => ({
  own: room.makeAction('own'), req: room.makeAction('req'), acc: room.makeAction('acc'),
  inv: room.makeAction('inv'), ack: room.makeAction('ack'),
  call: room.makeAction('call'), cans: room.makeAction('cans'), bye: room.makeAction('bye')
})
let inbox = null, myUid = null, myKod = null

async function openMyInbox() {
  if (inbox) { const old = inbox; inbox = null; old.room.leave().catch(() => {}) }
  const num = DB.me.number
  const room = joinRoom(cfg(inboxPass(num)), inboxRoomId(num))
  watchErrors(room)
  const A = inboxActions(room)
  const me = {room, A, num}
  inbox = me
  const self = await room.getSelf(); myUid = self.userId; myKod = await kodOf(myUid)
  room.onPeerJoin(({peerId}) => A.own.send({number: num, nick: DB.me.nick}, {target: peerId}).catch(() => {}))

  A.req.onMessage((d, {userId, peerId}) => {
    const number = cleanNum(d?.number); if (!number || userId === myUid) return
    const nick = cleanNick(d.nick)
    if (DB.contacts[userId]) {
      Object.assign(DB.contacts[userId], {number, nick}); save(); renderHome()
      A.acc.send({number: DB.me.number, nick: DB.me.nick}, {target: peerId}).catch(() => {})
      return
    }
    addNotice({type: 'req', key: 'req:' + userId, uid: userId, peerId, number, nick})
    notify('groupchat', 'Nowa prośba o kontakt')
  })

  A.inv.onMessage((d, {userId, peerId}) => {
    const c = DB.contacts[userId]; if (!c || !d || typeof d.gid !== 'string' || typeof d.secret !== 'string') return
    A.ack.send({gid: d.gid}, {target: peerId}).catch(() => {})
    if (DB.groups[d.gid] || notices.some(n => n.key === 'inv:' + d.gid)) return
    addNotice({type: 'inv', key: 'inv:' + d.gid, uid: userId, gid: d.gid.slice(0, 64), secret: d.secret.slice(0, 64),
      name: d.dm ? c.nick : cleanNick(d.name), dm: !!d.dm, nick: c.nick})
    notify('groupchat', 'Zaproszenie do czatu')
  })

  A.call.onMessage((d, {userId, peerId}) => onIncomingCall(d, userId, peerId))
  A.bye.onMessage((d, {userId}) => {
    if (call && call.role === 'in' && d?.id === call.id && userId === call.uid) endCall('Rozmówca się rozłączył')
  })
}

// Odwiedzanie cudzej skrzynki
const visits = new Map()
const sentReqs = new Map()   // numer → uid, do którego wysłano prośbę
function touch(v) {
  clearTimeout(v.timer)
  v.timer = setTimeout(() => {
    if (v.busy > 0) return touch(v)
    v.room.leave().catch(() => {}); visits.delete(v.num)
  }, 120000)
}
function visit(num) {
  let v = visits.get(num)
  if (v) { touch(v); return v }
  const room = joinRoom(cfg(inboxPass(num)), inboxRoomId(num))
  watchErrors(room)
  const A = inboxActions(room)
  v = {num, room, A, owners: new Map(), timer: null, busy: 0}
  A.own.onMessage((d, {userId, peerId}) => {
    if (String(d?.number) !== num || userId === myUid) return
    v.owners.set(userId, {peerId, userId, nick: cleanNick(d.nick)})
  })
  room.onPeerLeave(({peerId}) => { for (const [u, o] of v.owners) if (o.peerId === peerId) v.owners.delete(u) })
  A.acc.onMessage((d, {userId}) => {
    if (sentReqs.get(num) !== userId) return
    sentReqs.delete(num)
    const isNew = !DB.contacts[userId]
    DB.contacts[userId] = {...(DB.contacts[userId] || {}), number: num, nick: cleanNick(d?.nick), added: Date.now()}
    save(); renderHome(); processOutbox()
    addFlow?.onAccepted?.(userId)
    if (isNew && !addFlow) toast(`${cleanNick(d?.nick)} przyjął(-ęła) twoją prośbę`)
  })
  A.ack.onMessage((d, {userId}) => {
    const before = DB.outbox.length
    DB.outbox = DB.outbox.filter(i => !(i.uid === userId && i.gid === d?.gid))
    if (DB.outbox.length !== before) { save(); if (openGid) renderChatHead() }
  })
  A.cans.onMessage((d, {userId}) => onCallAnswer(d, userId))
  visits.set(num, v); touch(v)
  return v
}
function waitOwners(v, uid, ms) {
  return new Promise(res => {
    const t0 = Date.now()
    const tick = () => {
      const list = [...v.owners.values()]
      const hit = uid ? list.filter(o => o.userId === uid) : list
      if (hit.length && (uid || Date.now() - t0 > 3500)) return res(hit)
      if (Date.now() - t0 > ms) return res(hit)
      setTimeout(tick, 400)
    }
    tick()
  })
}

// Kolejka zaproszeń do grup (dostarczane, gdy znajomy będzie online)
let outboxBusy = false
async function processOutbox() {
  if (outboxBusy || !myUid) return
  outboxBusy = true
  try {
    DB.outbox = DB.outbox.filter(i => DB.contacts[i.uid] && DB.groups[i.gid] && Date.now() - i.ts < 7 * 864e5)
    const byUid = new Map()
    for (const i of DB.outbox) { if (!byUid.has(i.uid)) byUid.set(i.uid, []); byUid.get(i.uid).push(i) }
    for (const [uid, items] of byUid) {
      const c = DB.contacts[uid]; const v = visit(c.number); v.busy++
      try {
        const [o] = await waitOwners(v, uid, 9000)
        if (!o) continue
        for (const it of items) {
          const g = DB.groups[it.gid]; if (!g) continue
          await v.A.inv.send({gid: g.gid, secret: g.secret, name: g.name, dm: !!g.dm}, {target: o.peerId}).catch(() => {})
        }
      } finally { v.busy-- }
    }
  } finally { outboxBusy = false; save() }
}
function queueInvite(uid, gid) {
  if (DB.outbox.some(i => i.uid === uid && i.gid === gid)) return
  DB.outbox.push({uid, gid, ts: Date.now()}); save(); processOutbox()
}

// ═════════════════════════ HISTORIA NA TELEFONIE
// Wiadomości, zdjęcia i filmiki zapisują się w IndexedDB, zaszyfrowane kluczem urządzenia (AES-GCM, nieeksportowalny).
const reqP = q => new Promise((res, rej) => { q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error) })
let idbP = null, devKeyP = null
function idb() {
  return idbP ||= new Promise((res, rej) => {
    const q = indexedDB.open('groupchat-hist', 1)
    q.onupgradeneeded = () => { const db = q.result; db.createObjectStore('msgs', {keyPath: 'k'}).createIndex('gid', 'gid'); db.createObjectStore('keys') }
    q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error)
  })
}
function devKey() {
  return devKeyP ||= (async () => {
    const db = await idb()
    let k = await reqP(db.transaction('keys').objectStore('keys').get('dev'))
    if (!k) { k = await crypto.subtle.generateKey({name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']); await reqP(db.transaction('keys', 'readwrite').objectStore('keys').put(k, 'dev')) }
    return k
  })()
}
const storeFields = ({t, id, ts, text, nick, number, ttl, from, mime, dur, x, keep}) => ({t, id, ts, text, nick, number, ttl, from, mime, dur, x, keep})
async function histPut(gid, m) {
  if (m.t === 'sys') return
  try {
    const k = await devKey()
    const data = await encJ(k, storeFields(m))
    let bin = null
    if (m.url) bin = await encB(k, await (await fetch(m.url)).arrayBuffer())
    const db = await idb(); await reqP(db.transaction('msgs', 'readwrite').objectStore('msgs').put({k: gid + '|' + m.id, gid, ts: m.ts, data, bin}))
  } catch {}
}
async function histDel(gid, id) { try { const db = await idb(); await reqP(db.transaction('msgs', 'readwrite').objectStore('msgs').delete(gid + '|' + id)) } catch {} }
async function histClear(gid) {
  try {
    const db = await idb(); const st = db.transaction('msgs', 'readwrite').objectStore('msgs')
    const keys = await reqP(st.index('gid').getAllKeys(gid)); for (const k of keys) st.delete(k)
  } catch {}
}
async function histLoad(gid) {
  try {
    const k = await devKey(); const db = await idb()
    const rows = await reqP(db.transaction('msgs').objectStore('msgs').index('gid').getAll(gid))
    const out = []
    for (const row of rows.sort((a, b) => a.ts - b.ts).slice(-2000)) {
      try {
        const m = await decJ(k, row.data)
        if (row.bin) m.url = URL.createObjectURL(new Blob([await decB(k, row.bin)], {type: m.mime || 'application/octet-stream'}))
        m.stored = true; out.push(m)
      } catch {}
    }
    return out
  } catch { return [] }
}

// ═════════════════════════ GRUPY
const G = new Map()     // gid → stan w pamięci
let openGid = null

// ═════════════════════════ KOD ROZMOWY (dyktowany przez telefon)
// 12 cyfr (~40 bitów). Klucz = HKDF( sekret grupy ‖ PBKDF2-SHA256(kod, 600 000 iteracji) ).
// Bez kodu wiadomości są nieczytelne – także dla kogoś, kto zdobył zaproszenie do grupy.
const CODE_ITER = 600000
const PEND = Symbol('pend')
function genCode() {
  let s = ''
  while (s.length < 12) for (const x of crypto.getRandomValues(new Uint8Array(16))) if (x < 250 && s.length < 12) s += x % 10
  return s
}
const normCode = c => String(c || '').replace(/\D/g, '')
function codeProblem(c) {
  if (c.length !== 12) return 'Kod musi mieć 12 cyfr'
  if (/^(\d)\1+$/.test(c)) return 'Za prosty kod (same te same cyfry)'
  if ('01234567890123456789'.includes(c) || '98765432109876543210'.includes(c)) return 'Za prosty kod (kolejne cyfry)'
  if (/^(\d{3})\1{3}$/.test(c) || /^(\d{6})\1$/.test(c) || /^(\d{2})\1{5}$/.test(c)) return 'Za prosty kod (powtarzający się wzór)'
  return null
}
// 4 pola po 3 cyfry – każdą cyfrę można poprawić
function codeBoxes(initial = '', {readonly = false, onEnter} = {}) {
  const ins = [0, 1, 2, 3].map(i => h('input', {class: 'in codebox', inputmode: 'numeric', autocomplete: 'off', placeholder: '000', readOnly: readonly}))
  const set = c => { c = normCode(c); ins.forEach((el, i) => { el.value = c.slice(i * 3, i * 3 + 3) }) }
  ins.forEach((el, i) => {
    el.addEventListener('input', () => {
      const v = normCode(el.value)
      if (v.length > 3) { set(ins.slice(0, i).map(x => x.value).join('') + v); ins[Math.min(3, Math.floor((i * 3 + v.length) / 3))]?.focus(); return }
      el.value = v
      if (v.length === 3 && i < 3) { ins[i + 1].focus(); ins[i + 1].select() }
    })
    el.addEventListener('keydown', e => {
      if (e.key === 'Backspace' && !el.value && i > 0) { ins[i - 1].focus() }
      if (e.key === 'Enter') onEnter?.()
    })
    el.addEventListener('focus', () => el.select())
  })
  set(initial)
  return {el: h('div', {class: 'codeboxes'}, ins), get: () => ins.map(x => normCode(x.value)).join(''), set, focus: () => ins.find(x => x.value.length < 3)?.focus() || ins[0].focus(), ins}
}
const fmtCode = c => normCode(c).replace(/(\d{3})(?=\d)/g, '$1 ')
async function codeMaterial(g, epoch, code) {
  const pw = await crypto.subtle.importKey('raw', te.encode(normCode(code)), 'PBKDF2', false, ['deriveBits'])
  const bits = new Uint8Array(await crypto.subtle.deriveBits({name: 'PBKDF2', hash: 'SHA-256', salt: te.encode(`gc-code|${g.gid}|${epoch}`), iterations: CODE_ITER}, pw, 512))
  const ikm = new Uint8Array([...unb64(g.secret), ...bits.slice(0, 32)])
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey'])
  const key = await crypto.subtle.deriveKey({name: 'HKDF', hash: 'SHA-256', salt: te.encode('groupchat-code-v1'), info: te.encode(`${g.gid}|${epoch}`)},
    base, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt'])
  const check = b64(new Uint8Array(await crypto.subtle.digest('SHA-256', bits.slice(32))).slice(0, 12))
  return {key, check}
}
const cleanAnn = a => (a && typeof a.epoch === 'string' && typeof a.check === 'string')
  ? {epoch: a.epoch.slice(0, 32), check: a.check.slice(0, 32), nick: cleanNick(a.nick), ts: Number(a.ts) || Date.now()} : null
const annLess = (a, b) => a.ts < b.ts || (a.ts === b.ts && a.epoch < b.epoch)

const starting = new Map()
function startGroup(gid) {
  if (G.has(gid)) return Promise.resolve(G.get(gid))
  if (!starting.has(gid)) starting.set(gid, startGroupInner(gid).finally(() => starting.delete(gid)))
  return starting.get(gid)
}
async function startGroupInner(gid) {
  if (G.has(gid)) return G.get(gid)
  const g = DB.groups[gid]
  g.lockLog ??= []
  const key = await groupKey(gid, g.secret)
  const room = joinRoom(cfg(g.secret), 'g-' + gid)
  watchErrors(room)
  const A = {
    hi: room.makeAction('hi'), msg: room.makeAction('msg'), media: room.makeAction('media'),
    typ: room.makeAction('typ'), hist: room.makeAction('hist', {kind: 'request'}), lock: room.makeAction('lock'), ok: room.makeAction('ok'), gcall: room.makeAction('gcall'), exp: room.makeAction('exp')
  }
  const r = {gid, key, room, A, msgs: new Map(), online: new Map(), typing: new Map(), unread: 0, histAsked: false, prog: new Map(),
    ekeys: new Map(), pending: [], cands: [], candEntries: [], memCode: null, entryMsg: ''}
  G.set(gid, r)
  const locked = () => !!g.lock?.epoch
  r.needCode = () => !locked() || !r.ekeys.has(g.lock.epoch)
  r.curKey = () => locked() ? r.ekeys.get(g.lock.epoch) : null
  // potwierdzenia: kto udowodnił, że zna aktualny kod (wiadomość zaszyfrowana tym kodem)
  r.confirmedBy = () => (g.conf?.epoch === g.lock?.epoch ? g.conf.uids : [])
  r.canTalk = () => !r.needCode() && r.confirmedBy().length > 0
  r.sendOk = async target => { if (r.curKey()) A.ok.send(await r.seal({ok: g.lock.epoch}), target ? {target} : undefined).catch(() => {}) }
  r.addConfirm = uid => {
    if (!g.lock || uid === myUid) return
    if (g.conf?.epoch !== g.lock.epoch) g.conf = {epoch: g.lock.epoch, uids: []}
    if (g.conf.uids.includes(uid)) return
    g.conf.uids.push(uid); save()
    sysMsg(r, `✅ ${nameOf(g, uid)} potwierdził(a) kod rozmowy`)
    if (openGid === gid) renderLock()
    refreshGroup(r)
  }
  r.seal = async obj => ({e: g.lock.epoch, c: await encJ(r.curKey(), obj)})
  r.open = async d => {
    if (!d || typeof d !== 'object' || typeof d.e !== 'string') throw new Error('bez kodu')   // czaty bez kodu nie są akceptowane
    const k = r.ekeys.get(d.e); if (!k) return PEND
    return decJ(k, d.c)
  }
  const hello = async target => A.hi.send(await encJ(key, {nick: DB.me.nick, number: DB.me.number}), target ? {target} : undefined).catch(() => {})
  r.hello = hello
  r.sendLock = async target => { if (g.lockLog.length) A.lock.send(await encJ(key, {log: g.lockLog.slice(-6)}), target ? {target} : undefined).catch(() => {}) }

  // ── obsługa przychodzących (z kolejką „czeka na kod”)
  const queue = it => { r.pending.push(it); if (r.pending.length > 300) r.pending.shift(); if (openGid === gid) renderLock() }
  r.handleMsg = async (d, userId) => {
    try { const m = await r.open(d); if (m === PEND) return queue({k: 'msg', d, userId}); if (m?.t === 'm') addMsg(r, {...m, from: userId}) } catch {}
  }
  r.handleMedia = async (bytes, metadata, userId) => {
    try {
      const hd = await r.open(metadata?.h)
      if (hd === PEND) { if (r.pending.filter(p => p.k === 'media').length < 10) queue({k: 'media', bytes, metadata, userId}); return }
      if (hd.t !== 'img' && hd.t !== 'vid') return
      const buf = await decB(r.ekeys.get(metadata.h.e), bytes)
      const mime = /^(image|video)\/[\w.+-]+$/.test(hd.mime) ? hd.mime : (hd.t === 'img' ? 'image/jpeg' : 'video/mp4')
      addMsg(r, {...hd, from: userId, url: URL.createObjectURL(new Blob([buf], {type: mime}))})
    } catch {}
  }
  r.handleOk = async (d, userId) => {
    try { const p = await r.open(d); if (p === PEND) return queue({k: 'ok', d, userId}); if (p?.ok && p.ok === d.e && p.ok === g.lock?.epoch) r.addConfirm(userId) } catch {}
  }
  r.handleHist = async res => {
    try { const list = await r.open(res); if (list === PEND) return queue({k: 'hist', d: res}); if (Array.isArray(list)) for (const m of list.slice(-200)) addMsg(r, m, true) } catch {}
  }
  r.flushPending = async () => {
    const items = r.pending; r.pending = []
    for (const it of items) {
      if (it.k === 'msg') await r.handleMsg(it.d, it.userId)
      else if (it.k === 'media') await r.handleMedia(it.bytes, it.metadata, it.userId)
      else if (it.k === 'hist') await r.handleHist(it.d)
      else if (it.k === 'ok') await r.handleOk(it.d, it.userId)
    }
    if (openGid === gid) renderLock()
  }

  // ── stan kodu: dziennik zmian, każda zmiana podpisana poprzednim kodem
  r.applyLog = async (log, fromUid) => {
    let changed = false
    for (const e of (Array.isArray(log) ? log : []).slice(-6)) {
      const ann = cleanAnn(e?.a); if (!ann || g.lock?.epoch === ann.epoch) continue
      let proven = false
      if (typeof e.pe === 'string' && r.ekeys.has(e.pe)) {
        try { const q = await decJ(r.ekeys.get(e.pe), e.pc); proven = q?.epoch === ann.epoch && q?.check === ann.check } catch {}
      }
      const initialOnly = !g.lockLog.some(x => x.pe)
      const entry = {a: ann, pe: typeof e.pe === 'string' ? e.pe : undefined, pc: typeof e.pc === 'string' ? e.pc : undefined}
      if (!g.lock || (proven && e.pe === g.lock.epoch)) {
        g.lock = ann; g.lockLog.push(entry); changed = true
        sysMsg(r, `🔒 ${ann.nick} ${entry.pe ? 'zmienił(a) kod rozmowy' : 'zabezpieczył(a) rozmowę kodem'}`)
      } else if (!entry.pe && initialOnly && annLess(ann, g.lock)) {
        // dwie osoby wygenerowały kod jednocześnie – wygrywa wcześniejszy
        g.lock = ann; g.lockLog = [entry]; changed = true
        sysMsg(r, `🔒 ${ann.nick} wygenerował(a) kod chwilę wcześniej – obowiązuje jego/jej kod`)
      } else if (!r.ekeys.has(g.lock.epoch) && !r.cands.some(c => c.epoch === ann.epoch)) {
        r.cands.push(ann); r.candEntries.push(entry)
      }
    }
    if (changed) {
      g.lockLog = g.lockLog.slice(-6)
      if (g.codes && !g.codes[g.lock.epoch]) delete g.codes
      save(); await r.tryStoredCode()
      refreshGroup(r); if (openGid === gid) renderLock()
    }
  }
  r.tryStoredCode = async () => {
    const c = g.lock && (g.codes?.[g.lock.epoch] || r.memCode)
    if (c && !r.ekeys.has(g.lock.epoch)) {
      const {key: k, check} = await codeMaterial(g, g.lock.epoch, c)
      if (check === g.lock.check) { r.ekeys.set(g.lock.epoch, k); await r.flushPending(); r.sendOk() }
    }
  }
  r.unlock = async (code, remember) => {
    code = normCode(code)
    for (const ann of [g.lock, ...r.cands].filter(Boolean)) {
      const {key: k, check} = await codeMaterial(g, ann.epoch, code)
      if (check !== ann.check) continue
      r.ekeys.set(ann.epoch, k)
      if (ann !== g.lock) { g.lock = ann; g.lockLog.push({a: ann}) }
      if (remember) g.codes = {[ann.epoch]: code}; else { delete g.codes; r.memCode = code }
      // czy po tym kodzie była już poprawka (podpisana tym kodem)? wtedy to stary kod
      const ce = r.candEntries; r.cands = []; r.candEntries = []
      if (ce.length) await r.applyLog(ce)
      save()
      if (g.lock.epoch !== ann.epoch && !r.ekeys.has(g.lock.epoch)) { refreshGroup(r); return 'old' }
      await r.flushPending(); r.sendOk(); refreshGroup(r)
      return true
    }
    return false
  }
  r.setCode = async (code, remember) => {
    code = normCode(code)
    const weak = codeProblem(code); if (weak) throw new Error(weak)
    const old = g.lock?.epoch, oldKey = old && r.ekeys.get(old)
    if (old && !oldKey) throw new Error('Najpierw wpisz obecny kod')
    const epoch = hex(rnd(8))
    const {key: k, check} = await codeMaterial(g, epoch, code)
    const ann = {epoch, check, nick: DB.me.nick, ts: Date.now()}
    const entry = {a: ann}
    if (old) { entry.pe = old; entry.pc = await encJ(oldKey, ann) }
    g.lock = ann; g.lockLog = [...g.lockLog, entry].slice(-6); r.ekeys.set(epoch, k)
    if (remember) g.codes = {[epoch]: code}; else { delete g.codes; r.memCode = code }
    save(); await r.sendLock(); r.sendOk()
    sysMsg(r, old ? '🔒 Ustawiono nowy kod rozmowy' : '🔒 Rozmowa zabezpieczona kodem')
    refreshGroup(r)
  }
  if (g.lock) r.tryStoredCode().then(() => { if (openGid === gid) renderLock() })

  room.onPeerJoin(async ({peerId}) => {
    hello(peerId); await r.sendLock(peerId); r.sendOk(peerId)
    if (!r.histAsked) {
      r.histAsked = true
      try { const res = await A.hist.request({}, {target: peerId, timeoutMs: 12000}); if (res && !res.none) r.handleHist(res) }
      catch { r.histAsked = false }
    }
  })
  room.onPeerLeave(({peerId, userId}) => {
    const set = r.online.get(userId)
    if (set) { set.delete(peerId); if (!set.size) { r.online.delete(userId); sysMsg(r, `${nameOf(g, userId)} – offline`) } }
    refreshGroup(r)
  })
  A.hi.onMessage(async (d, {userId, peerId}) => {
    try {
      const p = await decJ(key, d)
      const first = !r.online.has(userId)
      if (first) r.online.set(userId, new Set())
      r.online.get(userId).add(peerId)
      g.seen[userId] = {nick: cleanNick(p.nick), number: cleanNum(p.number)}; save()
      if (first) sysMsg(r, `${nameOf(g, userId)} – online`)
      refreshGroup(r)
    } catch {}
  })
  A.ok.onMessage((d, {userId}) => r.handleOk(d, userId))
  r.seenCalls = new Set()
  A.gcall.onMessage(async (d, {userId}) => {
    try {
      const p = await r.open(d); if (p === PEND || !p || typeof p.id !== 'string') return
      if (p.end) { if (r.activeCall?.id === p.id && r.activeCall.from === userId) { r.activeCall = null; renderCallBanner() } return }
      r.activeCall = {id: p.id.slice(0, 32), video: !!p.video, nick: cleanNick(p.nick), ts: Date.now(), from: userId}
      renderCallBanner()
      if (!r.seenCalls.has(p.id) && !p.hb) { r.seenCalls.add(p.id); if (!call && !gcall) ringGroupCall(r, r.activeCall) }
      r.seenCalls.add(p.id)
    } catch {}
  })
  A.lock.onMessage(async (d, {userId}) => { try { const p = await decJ(key, d); await r.applyLog(p?.log, userId) } catch {} })
  A.msg.onMessage((d, {userId}) => r.handleMsg(d, userId))
  A.media.onReceive(({byteLength}) => byteLength <= MAX_RX)
  A.media.onReceiveProgress((p, {userId}) => {
    r.prog.set(userId, p); if (openGid === gid) renderTyping()
    if (p >= 1) r.prog.delete(userId)
  })
  A.media.onMessage(async (bytes, {userId, metadata}) => {
    r.prog.delete(userId); await r.handleMedia(bytes, metadata, userId)
    if (openGid === gid) renderTyping()
  })
  A.typ.onMessage((d, {userId}) => {
    clearTimeout(r.typing.get(userId))
    r.typing.set(userId, setTimeout(() => { r.typing.delete(userId); if (openGid === gid) renderTyping() }, 4000))
    if (openGid === gid) renderTyping()
  })
  A.hist.onRequest(async () => {
    if (r.needCode()) return {none: 1}
    return r.seal([...r.msgs.values()]
      .filter(m => m.t === 'm' && !(m.exp && m.exp < Date.now()))
      .slice(-150).map(({t, id, ts, text, nick, number, ttl, from, x}) => ({t, id, ts, text, nick, number, ttl, from, x})))
  })
  // ── „Ma zniknąć?” – nadawca potwierdza, wiadomość znika u wszystkich za 10 minut
  r.handleExp = async (d, userId) => {
    try {
      const p = await r.open(d); if (p === PEND || !p) return
      const m = r.msgs.get(p.id); if (!m || m.from !== userId) return
      m.x = Math.min(Number(p.x) || 0, Date.now() + 15 * 60e3); m.exp = m.x; histPut(gid, m); refreshMsgEl(r, m)
    } catch {}
  }
  A.exp.onMessage((d, {userId}) => r.handleExp(d, userId))
  // wczytaj zapisaną historię
  histLoad(gid).then(list => { for (const m of list) addMsg(r, m, true); if (openGid === gid) openChat(gid) })
  return r
}

function nameOf(g, uid) {
  if (uid === myUid) return 'Ty'
  return DB.contacts[uid]?.nick || g?.seen?.[uid]?.nick || 'Ktoś'
}

function addMsg(r, m, fromHist = false) {
  if (!m || typeof m.id !== 'string') return
  const ex = r.msgs.get(m.id)
  if (ex) {   // znana wiadomość – ewentualnie przejmij „ma zniknąć” od nadawcy
    if (Number(m.x) > 0 && !ex.x && m.from === ex.from) { ex.x = Number(m.x); ex.exp = ex.x; histPut(r.gid, ex); refreshMsgEl(r, ex) }
    return
  }
  const now = Date.now()
  m.ts = Math.min(Number(m.ts) || now, now)
  m.ttl = Math.max(0, Math.min(Number(m.ttl) || 0, 7 * 86400))
  m.x = Number(m.x) > 0 ? Math.min(Number(m.x), now + 24 * 3600e3) : 0
  m.exp = m.x || (m.ttl ? m.ts + m.ttl * 1000 : 0)
  if (m.exp && m.exp < now) { if (m.stored) histDel(r.gid, m.id); return }
  if (m.t !== 'sys' && !m.stored) histPut(r.gid, m)
  if (m.t === 'm') m.text = String(m.text || '').slice(0, 4000)
  r.msgs.set(m.id, m)
  if (r.msgs.size > 1500) { const [k, old] = r.msgs.entries().next().value; if (old.url) URL.revokeObjectURL(old.url); r.msgs.delete(k) }
  const mine = m.from === myUid
  if (openGid === r.gid && !document.hidden) insertMsgEl(m)
  else if (!mine && m.t !== 'sys' && !m.stored) {
    r.unread++
    if (openGid === r.gid) insertMsgEl(m)
    if (!fromHist) notify('groupchat', 'Nowa wiadomość')
  }
  if (!mine && m.t !== 'sys' && r.typing.has(m.from)) { clearTimeout(r.typing.get(m.from)); r.typing.delete(m.from); if (openGid === r.gid) renderTyping() }
  updateTitle(); renderHomeSoon()
}
function sysMsg(r, text) { addMsg(r, {t: 'sys', id: 's' + hex(rnd(6)), ts: Date.now(), text, from: myUid}) }

// znikające wiadomości
setInterval(() => {
  const now = Date.now()
  for (const r of G.values()) for (const [id, m] of r.msgs) {
    if (m.exp && m.exp < now) {
      r.msgs.delete(id); if (m.url) URL.revokeObjectURL(m.url); histDel(r.gid, id)
      document.querySelector(`[data-mid="${CSS.escape(id)}"]`)?.remove(); renderHomeSoon()
    }
  }
}, 3000)

async function sendText(r, text) {
  const g = DB.groups[r.gid]
  const m = {t: 'm', id: hex(rnd(8)), ts: Date.now(), text, nick: DB.me.nick, number: DB.me.number, ttl: g.ttl || 0}
  if (!r.canTalk()) return toast('Najpierw ustalcie i zatwierdźcie kod rozmowy')
  addMsg(r, {...m, from: myUid})
  r.A.msg.send(await r.seal(m)).catch(() => {})
}

// ── zdjęcia i filmiki
async function shrinkImage(file) {
  if (file.type === 'image/gif' && file.size < 4e6) return file
  let bmp
  try { bmp = await createImageBitmap(file, {imageOrientation: 'from-image'}) } catch { bmp = await createImageBitmap(file) }
  const s = Math.min(1, 1600 / Math.max(bmp.width, bmp.height))
  const c = document.createElement('canvas'); c.width = Math.round(bmp.width * s); c.height = Math.round(bmp.height * s)
  c.getContext('2d').drawImage(bmp, 0, 0, c.width, c.height); bmp.close?.()
  return new Promise((res, rej) => c.toBlob(b => b ? res(b) : rej(new Error('jpeg')), 'image/jpeg', 0.82))
}
function videoDuration(file) {
  return new Promise(res => {
    const v = document.createElement('video'); v.preload = 'metadata'; const u = URL.createObjectURL(file)
    const done = d => { URL.revokeObjectURL(u); res(d) }
    v.onloadedmetadata = () => done(v.duration); v.onerror = () => done(NaN); v.src = u
    setTimeout(() => done(NaN), 8000)
  })
}
// Kompresja filmiku w przeglądarce (do ~480p, ~1 Mb/s). Trwa tyle, co filmik.
async function compressVideo(file, onP) {
  if (!window.MediaRecorder || !HTMLCanvasElement.prototype.captureStream || !window.AudioContext) throw new Error('brak')
  const url = URL.createObjectURL(file)
  const v = document.createElement('video'); v.src = url; v.playsInline = true
  await new Promise((res, rej) => { v.onloadedmetadata = res; v.onerror = rej })
  const s = Math.min(1, 854 / Math.max(v.videoWidth || 854, v.videoHeight || 480))
  const w = Math.max(2, Math.round((v.videoWidth || 854) * s / 2) * 2), hgt = Math.max(2, Math.round((v.videoHeight || 480) * s / 2) * 2)
  const c = document.createElement('canvas'); c.width = w; c.height = hgt; const ctx = c.getContext('2d')
  const out = c.captureStream(30)
  const ac = new AudioContext(); const src = ac.createMediaElementSource(v); const dst = ac.createMediaStreamDestination()
  src.connect(dst); dst.stream.getAudioTracks().forEach(t => out.addTrack(t)); await ac.resume()
  const types = ['video/mp4;codecs=avc1.42E01E,mp4a.40.2', 'video/webm;codecs=vp8,opus', 'video/webm']
  const mt = types.find(t => MediaRecorder.isTypeSupported(t)) || ''
  const rec = new MediaRecorder(out, {mimeType: mt || undefined, videoBitsPerSecond: 1_000_000, audioBitsPerSecond: 64000})
  const chunks = []; rec.ondataavailable = e => e.data.size && chunks.push(e.data)
  const stopped = new Promise(res => { rec.onstop = res })
  let alive = true
  const draw = () => { if (!alive) return; ctx.drawImage(v, 0, 0, w, hgt); onP(v.duration ? v.currentTime / v.duration : 0); requestAnimationFrame(draw) }
  rec.start(1000)
  try { await v.play() } catch (e) { rec.stop(); ac.close(); URL.revokeObjectURL(url); throw e }
  draw()
  await new Promise(res => { v.onended = res; setTimeout(res, ((v.duration || 30) + 4) * 1000) })
  alive = false; rec.stop(); await stopped; ac.close(); URL.revokeObjectURL(url)
  const blob = new Blob(chunks, {type: (mt.split(';')[0] || 'video/webm')})
  if (!blob.size || blob.size >= file.size) throw new Error('bez zysku')
  return blob
}
async function sendFile(r, file) {
  const g = DB.groups[r.gid]
  if (!r.canTalk()) return toast('Najpierw ustalcie i zatwierdźcie kod rozmowy')
  const kind = file.type.startsWith('video/') ? 'vid' : file.type.startsWith('image/') ? 'img' : null
  if (!kind) return toast('Można wysyłać zdjęcia i filmiki')
  let blob = file, extra = {}
  try {
    if (kind === 'img') blob = await shrinkImage(file)
    else {
      const d = await videoDuration(file)
      if (isFinite(d) && d > MAX_VIDEO_S + 0.9) return toast(`Filmik może mieć maksymalnie ${MAX_VIDEO_S} sekund (ten ma ${Math.round(d)} s)`)
      if (isFinite(d)) extra.dur = Math.round(d)
      if (file.size > COMPRESS_OVER) {
        try { blob = await compressVideo(file, p => toast(`Kompresuję filmik… ${Math.round(p * 100)}%`, 2000)) }
        catch { blob = file }
      }
      if (blob.size > MAX_MEDIA) return toast(`Filmik ma ${mb(blob.size)} MB – limit to ${mb(MAX_MEDIA)} MB. Nagraj w niższej jakości (720p).`, 6000)
    }
  } catch { return toast('Nie udało się przygotować pliku') }
  const hd = {t: kind, id: hex(rnd(8)), ts: Date.now(), nick: DB.me.nick, number: DB.me.number, ttl: g.ttl || 0, mime: blob.type || file.type, ...extra}
  const m = {...hd, from: myUid, url: URL.createObjectURL(blob), sending: 0}
  addMsg(r, m)
  if (!r.online.size) return
  const enc = await encB(r.curKey(), await blob.arrayBuffer())
  r.A.media.send(enc, {
    metadata: {h: await r.seal(hd)},
    onProgress: p => { m.sending = p; const bar = document.querySelector(`[data-mid="${m.id}"] .prog i`); if (bar) bar.style.width = Math.round(p * 100) + '%'; if (p >= 1) bar?.parentElement.remove() }
  }).catch(() => toast('Nie udało się wysłać pliku do wszystkich'))
}

// ═════════════════════════ ROZMOWY (audio / wideo, 1:1)
let call = null
async function getMedia(video) {
  return navigator.mediaDevices.getUserMedia({
    audio: {echoCancellation: true, noiseSuppression: true, autoGainControl: true},
    video: video ? {facingMode: 'user', width: {ideal: 640}, height: {ideal: 480}} : false
  })
}
let ringCtx = null, ringIv = null
function startRing() {
  try { navigator.vibrate?.([400, 200, 400, 200, 400]) } catch {}
  try {
    ringCtx = new AudioContext()
    const beep = () => {
      const o = ringCtx.createOscillator(), gn = ringCtx.createGain(); o.frequency.value = 660
      gn.gain.setValueAtTime(0.0001, ringCtx.currentTime); gn.gain.exponentialRampToValueAtTime(0.25, ringCtx.currentTime + 0.05)
      gn.gain.exponentialRampToValueAtTime(0.0001, ringCtx.currentTime + 0.9)
      o.connect(gn).connect(ringCtx.destination); o.start(); o.stop(ringCtx.currentTime + 1)
    }
    beep(); ringIv = setInterval(() => { beep(); try { navigator.vibrate?.([400, 200, 400]) } catch {} }, 2500)
  } catch {}
}
function stopRing() { clearInterval(ringIv); ringIv = null; try { ringCtx?.close() } catch {} ringCtx = null; try { navigator.vibrate?.(0) } catch {} }

async function startOutgoingCall(uid, video) {
  if (call || gcall) return toast('Trwa już rozmowa')
  const c = DB.contacts[uid]; if (!c) return
  call = {id: hex(rnd(8)), secret: b64(rnd(18)), video, uid, nick: c.nick, role: 'out', state: 'calling'}
  const me = call
  showCall(); setCallStatus('Łączenie…')
  try { me.stream = await getMedia(video) } catch { return endCall('Brak dostępu do mikrofonu' + (video ? '/kamery' : '')) }
  if (call !== me) return me.stream.getTracks().forEach(t => t.stop())
  showLocal()
  const v = visit(c.number); v.busy++; me.visit = v
  setCallStatus('Szukam ' + c.nick + '…')
  const [o] = await waitOwners(v, uid, 15000)
  if (call !== me || me.state !== 'calling') return
  if (!o) return endCall(`${c.nick} jest offline (musi mieć otwartą aplikację)`)
  me.ownerPeer = o.peerId
  await v.A.call.send({id: me.id, secret: me.secret, video}, {target: o.peerId}).catch(() => {})
  setCallStatus('Dzwoni…')
  me.ringTimer = setTimeout(() => {
    if (call === me && me.state === 'calling') { v.A.bye.send({id: me.id}, {target: o.peerId}).catch(() => {}); endCall('Nikt nie odebrał') }
  }, 45000)
}
function onCallAnswer(d, userId) {
  if (!call || call.role !== 'out' || d?.id !== call.id || userId !== call.uid || call.state !== 'calling') return
  clearTimeout(call.ringTimer)
  if (d.ok) joinCallRoom()
  else endCall(d.busy ? `${call.nick} ma teraz inną rozmowę` : 'Połączenie odrzucone')
}
function onIncomingCall(d, userId, peerId) {
  const c = DB.contacts[userId]
  if (!c || !d || typeof d.id !== 'string' || typeof d.secret !== 'string') return
  if (call || gcall) { inbox.A.cans.send({id: d.id, ok: false, busy: true}, {target: peerId}).catch(() => {}); return }
  call = {id: d.id.slice(0, 40), secret: d.secret.slice(0, 64), video: !!d.video, uid: userId, nick: c.nick, role: 'in', state: 'ringing', peerId}
  showCall(); setCallStatus(d.video ? '🎥 Połączenie wideo' : '📞 Połączenie głosowe')
  startRing(); notify('groupchat', '📞 Połączenie przychodzące')
  const me = call
  me.ringTimer = setTimeout(() => { if (call === me && me.state === 'ringing') endCall('Nieodebrane połączenie') }, 50000)
}
async function acceptCall() {
  const me = call; if (!me || me.state !== 'ringing') return
  stopRing(); clearTimeout(me.ringTimer); me.state = 'connecting'; setCallStatus('Łączenie…'); renderCallCtl()
  try { me.stream = await getMedia(me.video) } catch {
    inbox.A.cans.send({id: me.id, ok: false}, {target: me.peerId}).catch(() => {})
    return endCall('Brak dostępu do mikrofonu' + (me.video ? '/kamery' : ''))
  }
  showLocal()
  inbox.A.cans.send({id: me.id, ok: true}, {target: me.peerId}).catch(() => {})
  joinCallRoom()
}
function declineCall() {
  if (!call) return
  if (call.role === 'in' && call.state === 'ringing') inbox.A.cans.send({id: call.id, ok: false}, {target: call.peerId}).catch(() => {})
  endCall()
}
function hangUp() {
  if (!call) return
  if (call.role === 'out' && call.state === 'calling' && call.ownerPeer) call.visit?.A.bye.send({id: call.id}, {target: call.ownerPeer}).catch(() => {})
  endCall()
}
function joinCallRoom() {
  const me = call; me.state = 'connecting'; setCallStatus('Łączenie…'); renderCallCtl()
  const room = joinRoom(cfg(me.secret), 'c-' + me.id); me.room = room; watchErrors(room)
  room.onPeerJoin(({peerId, userId}) => { if (userId === me.uid) room.addStream(me.stream, {target: peerId}).catch(() => {}) })
  room.onPeerStream((stream, {userId}) => {
    if (userId !== me.uid || call !== me) return
    const rv = $('#remoteV'); rv.srcObject = stream; rv.play().catch(() => {})
    me.state = 'live'; me.t0 = Date.now(); renderCallCtl()
    $('#remoteV').classList.toggle('hidden', !me.video); $('#call .info').classList.toggle('mini', me.video)
    clearInterval(me.clock); me.clock = setInterval(() => {
      const s = Math.floor((Date.now() - me.t0) / 1000); setCallStatus(`${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`)
    }, 1000)
    setCallStatus('0:00')
    showSas(me)
  })
  room.onPeerLeave(({userId}) => { if (userId === me.uid && call === me) endCall('Rozmowa zakończona') })
  me.connTimer = setTimeout(() => { if (call === me && me.state !== 'live') endCall('Nie udało się nawiązać połączenia. Spróbuj Wi-Fi albo ustaw serwer TURN.') }, 35000)
}
// Kod połączenia (SAS) – z odcisków certyfikatów DTLS obu stron. Ten sam u obu = nikt się nie wpiął.
async function callSas(room, uid) {
  const p = Object.values(room.getPeers()).find(x => x.userId === uid); const pc = p?.connection
  if (!pc) return null
  const fp = sdp => (/a=fingerprint:\S+ ([0-9A-Fa-f:]+)/.exec(sdp || '') || [])[1]?.toUpperCase()
  const a = fp(pc.localDescription?.sdp), b = fp(pc.remoteDescription?.sdp)
  if (!a || !b) return null
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode('gc-sas|' + [a, b].sort().join('|'))))
  return String(((d[0] << 16) | (d[1] << 8) | d[2]) % 1000000).padStart(6, '0').replace(/(\d{3})(\d{3})/, '$1 $2')
}
async function showSas(me) {
  for (let i = 0; i < 10 && call === me; i++) {
    const sas = await callSas(me.room, me.uid).catch(() => null)
    if (sas) {
      me.sas = sas
      const el = $('#callSas'); el.replaceChildren(h('b', {}, sas), 'Kod połączenia – powiedzcie go sobie. Inny? Rozłącz się!'); el.classList.remove('hidden')
      return
    }
    await sleep(700)
  }
}
function endCall(msg) {
  const me = call; if (!me) return
  call = null; stopRing()
  clearTimeout(me.ringTimer); clearTimeout(me.connTimer); clearInterval(me.clock)
  me.stream?.getTracks().forEach(t => t.stop())
  me.room?.leave().catch(() => {})
  if (me.visit) me.visit.busy--
  $('#remoteV').srcObject = null; $('#localV').srcObject = null
  $('#call').classList.add('hidden')
  if (msg) toast(msg, 4500)
}
function showCall() {
  $('#callAv').replaceWith(Object.assign(avatar(call.nick, call.uid, true), {id: 'callAv', style: `background:hsl(${hue(call.uid)} 55% 62%);margin:0 auto;width:96px;height:96px;font-size:40px`}))
  $('#callName').textContent = call.nick
  $('#remoteV').classList.add('hidden'); $('#localV').classList.add('hidden')
  $('#call .info').classList.remove('mini'); $('#callSas').classList.add('hidden'); $('#call').classList.remove('hidden'); renderCallCtl()
}
function showLocal() {
  if (!call?.video) return
  const lv = $('#localV'); lv.srcObject = call.stream; lv.classList.remove('hidden'); lv.play().catch(() => {})
}
const setCallStatus = s => { $('#callStatus').textContent = s }
function renderCallCtl() {
  const el = $('#callCtl'); el.replaceChildren()
  if (gcall) return renderGroupCtl()
  if (!call) return
  if (call.role === 'in' && call.state === 'ringing') {
    el.append(h('button', {class: 'red', onclick: declineCall, title: 'Odrzuć'}, '✕'), h('button', {class: 'green', onclick: acceptCall, title: 'Odbierz'}, '📞'))
    return
  }
  const aud = call.stream?.getAudioTracks()[0], vid = call.stream?.getVideoTracks()[0]
  el.append(h('button', {class: aud && !aud.enabled ? 'off' : '', title: 'Mikrofon', onclick: () => { if (aud) { aud.enabled = !aud.enabled; renderCallCtl() } }}, aud && !aud.enabled ? '🔇' : '🎙️'))
  if (call.video) {
    el.append(h('button', {class: vid && !vid.enabled ? 'off' : '', title: 'Kamera', onclick: () => { if (vid) { vid.enabled = !vid.enabled; renderCallCtl() } }}, '📷'))
    el.append(h('button', {title: 'Przełącz kamerę', onclick: flipCam}, '🔄'))
  }
  el.append(h('button', {class: 'red', onclick: hangUp, title: 'Rozłącz'}, '✕'))
}
async function flipCam() {
  const call = window.__curCall(); if (!call?.stream) return
  const old = call.stream.getVideoTracks()[0]; if (!old) return
  call.facing = call.facing === 'environment' ? 'user' : 'environment'
  try {
    const ns = await navigator.mediaDevices.getUserMedia({video: {facingMode: call.facing, width: {ideal: 640}}})
    const nt = ns.getVideoTracks()[0]
    if (call.room) await call.room.replaceTrack(old, nt).catch(() => {})
    call.stream.removeTrack(old); old.stop(); call.stream.addTrack(nt)
    const lv = gcall ? gcall.tiles.get('me')?.querySelector('video') : $('#localV')
    if (lv) { lv.srcObject = call.stream; lv.style.transform = call.facing === 'user' ? 'scaleX(-1)' : 'none' }
  } catch { toast('Nie można przełączyć kamery') }
}


// ═════════════════════════ ROZMOWY GRUPOWE (siatka, każdy z każdym)
// Pokój rozmowy: hasło = sekret grupy + id rozmowy + kod rozmowy → bez kodu nie da się dołączyć.
let gcall = null
window.__curCall = () => call || gcall
function codeOf(r) { const g = DB.groups[r.gid]; return g.codes?.[g.lock?.epoch] || r.memCode || '' }
function renderCallBanner() {
  const b = $('#callBanner'); if (!b) return
  const r = G.get(openGid); const ac = r?.activeCall
  const live = ac && Date.now() - ac.ts < 50000 && gcall?.id !== ac.id
  b.classList.toggle('hidden', !live)
  if (live) b.replaceChildren(h('span', {}, `${ac.video ? '🎥' : '📞'} Trwa rozmowa grupowa (${ac.nick})`),
    h('button', {class: 'btn', style: 'width:auto;margin:0;padding:8px 14px', onclick: () => startGroupCall(r.gid, ac.video, ac.id)}, 'Dołącz'))
}
setInterval(renderCallBanner, 10000)
function ringGroupCall(r, ac) {
  const g = DB.groups[r.gid]
  const ov = {ring: true, gid: r.gid, id: ac.id}
  gcall = null
  $('#callAv').replaceWith(Object.assign(avatar(g.name, g.gid, true), {id: 'callAv', style: `background:hsl(${hue(g.gid)} 55% 62%);margin:0 auto;width:96px;height:96px;font-size:40px`}))
  $('#callName').textContent = g.name
  setCallStatus(`${ac.video ? '🎥' : '📞'} ${ac.nick} zaprasza do rozmowy grupowej`)
  $('#grid').classList.add('hidden'); $('#remoteV').classList.add('hidden'); $('#localV').classList.add('hidden'); $('#callSas').classList.add('hidden')
  $('#call .info').classList.remove('mini'); $('#call').classList.remove('hidden')
  const close = () => { stopRing(); clearTimeout(ov.t); if (!gcall && !call) $('#call').classList.add('hidden') }
  $('#callCtl').replaceChildren(
    h('button', {class: 'red', title: 'Odrzuć', onclick: close}, '✕'),
    h('button', {class: 'green', title: 'Dołącz', onclick: () => { close(); startGroupCall(r.gid, ac.video, ac.id) }}, ac.video ? '🎥' : '📞'))
  startRing(); notify('groupchat', '📞 Rozmowa grupowa')
  ov.t = setTimeout(close, 40000)
}
function gTile(key, name, seed) {
  let t = gcall.tiles.get(key)
  if (!t) {
    t = h('div', {class: 'tile'}, avatar(name, seed, true), h('video', {autoplay: true, playsinline: true}), h('div', {class: 'nm'}, name))
    if (key === 'me') { const v = t.querySelector('video'); v.muted = true; v.style.transform = 'scaleX(-1)' }
    gcall.tiles.set(key, t); $('#grid').append(t); layoutGrid()
  }
  return t
}
function layoutGrid() {
  const n = gcall?.tiles.size || 1
  $('#grid').style.gridTemplateColumns = `repeat(${n <= 1 ? 1 : n <= 4 ? 2 : 3}, 1fr)`
  if (gcall) setCallStatus(`${n} ${n === 1 ? 'osoba' : n < 5 ? 'osoby' : 'osób'} w rozmowie`)
}
async function startGroupCall(gid, video, id = null) {
  if (call || gcall) return toast('Trwa już rozmowa')
  const r = G.get(gid), g = DB.groups[gid]
  if (!r?.canTalk()) return toast('Najpierw ustalcie i zatwierdźcie kod rozmowy')
  const code = codeOf(r); if (!code) return toast('Brak kodu rozmowy na tym telefonie – wpisz go ponownie (🔐)')
  const isNew = !id; id = id || hex(rnd(8))
  const me = gcall = {gid, id, video, tiles: new Map()}
  $('#callAv').replaceWith(Object.assign(avatar(g.name, g.gid, true), {id: 'callAv', style: 'display:none'}))
  $('#callName').textContent = g.name; setCallStatus('Łączenie…')
  $('#remoteV').classList.add('hidden'); $('#localV').classList.add('hidden'); $('#callSas').classList.add('hidden')
  $('#grid').replaceChildren(); $('#grid').classList.remove('hidden')
  $('#call .info').classList.add('mini'); $('#call').classList.remove('hidden')
  try { me.stream = await getMedia(video) } catch { return endGroupCall('Brak dostępu do mikrofonu' + (video ? '/kamery' : '')) }
  if (gcall !== me) return me.stream.getTracks().forEach(t => t.stop())
  renderCallCtl()
  const mine = gTile('me', DB.me.nick + ' (ty)', myUid)
  const mv = mine.querySelector('video'); mv.srcObject = me.stream; mv.play().catch(() => {}); mine.classList.toggle('vid', video)
  const room = joinRoom(cfg(`gc|${g.secret}|${id}|${code}`), 'gcall-' + gid + '-' + id); me.room = room; watchErrors(room)
  const who = room.makeAction('who')
  room.onPeerJoin(({peerId, userId}) => {
    room.addStream(me.stream, {target: peerId}).catch(() => {})
    who.send({nick: DB.me.nick}, {target: peerId}).catch(() => {})
    gTile(peerId, nameOf(g, userId), userId)
  })
  who.onMessage((d, {peerId, userId}) => { const t = gTile(peerId, nameOf(g, userId), userId); t.querySelector('.nm').textContent = DB.contacts[userId]?.nick || cleanNick(d?.nick) })
  room.onPeerStream((stream, {peerId, userId}) => {
    const t = gTile(peerId, nameOf(g, userId), userId); const v = t.querySelector('video')
    v.srcObject = stream; v.play().catch(() => {}); t.classList.toggle('vid', stream.getVideoTracks().length > 0)
  })
  room.onPeerLeave(({peerId}) => { gcall?.tiles.get(peerId)?.remove(); gcall?.tiles.delete(peerId); layoutGrid() })
  const announce = async (extra = {}) => r.A.gcall.send(await r.seal({id, video, nick: DB.me.nick, ...extra})).catch(() => {})
  me.announce = announce
  if (isNew) announce(); r.seenCalls.add(id)
  me.hb = setInterval(() => announce({hb: 1}), 20000)
  r.activeCall = {id, video, nick: DB.me.nick, ts: Date.now(), from: myUid}; renderCallBanner()
  layoutGrid()
}
function endGroupCall(msg) {
  const me = gcall; if (!me) return
  gcall = null
  clearInterval(me.hb)
  me.stream?.getTracks().forEach(t => t.stop())
  if (me.room) {
    const left = Object.keys(me.room.getPeers?.() || {}).length
    if (!left) me.announce?.({end: 1})
    me.room.leave().catch(() => {})
  }
  $('#grid').replaceChildren(); $('#grid').classList.add('hidden')
  $('#call').classList.add('hidden'); $('#call .info').classList.remove('mini')
  const r = G.get(me.gid); if (r?.activeCall?.id === me.id && r.activeCall.from === myUid) r.activeCall = null
  renderCallBanner()
  if (msg) toast(msg, 4500)
}
function renderGroupCtl() {
  const el = $('#callCtl'); el.replaceChildren()
  const c = gcall; if (!c?.stream) { el.append(h('button', {class: 'red', onclick: () => endGroupCall(), title: 'Rozłącz'}, '✕')); return }
  const aud = c.stream.getAudioTracks()[0], vid = c.stream.getVideoTracks()[0]
  el.append(h('button', {class: aud && !aud.enabled ? 'off' : '', title: 'Mikrofon', onclick: () => { if (aud) { aud.enabled = !aud.enabled; renderGroupCtl() } }}, aud && !aud.enabled ? '🔇' : '🎙️'))
  if (c.video) {
    el.append(h('button', {class: vid && !vid.enabled ? 'off' : '', title: 'Kamera', onclick: () => { if (vid) { vid.enabled = !vid.enabled; renderGroupCtl() } }}, '📷'))
    el.append(h('button', {title: 'Przełącz kamerę', onclick: flipCam}, '🔄'))
  }
  el.append(h('button', {class: 'red', onclick: () => endGroupCall(), title: 'Rozłącz'}, '✕'))
}

// ═════════════════════════ UI
const notices = []
function addNotice(n) { if (notices.some(x => x.key === n.key)) return; notices.push(n); renderHome() }
function dropNotice(key) { const i = notices.findIndex(n => n.key === key); if (i >= 0) notices.splice(i, 1); renderHome() }

function show(id) { for (const s of ['#onb', '#home', '#chat', '#pin']) $(s).classList.toggle('hidden', s !== id) }

function openSheet(title, ...content) {
  $('#sheetT').textContent = title; $('#sheetB').replaceChildren(...content.flat(3).filter(x => x != null && x !== false))
  $('#sheet').classList.remove('hidden'); $('#sheetBg').classList.remove('hidden')
}
function closeSheet() { $('#sheet').classList.add('hidden'); $('#sheetBg').classList.add('hidden'); addFlow = null }
$('#sheetX').onclick = closeSheet; $('#sheetBg').onclick = closeSheet

// ── onboarding
function showOnboarding() {
  show('#onb')
  $('#onbNum').value = randNum()
  $('#onbDice').onclick = () => { $('#onbNum').value = randNum() }
  $('#onbGo').onclick = () => {
    const number = cleanNum($('#onbNum').value.trim()); const nick = $('#onbNick').value.trim()
    if (!number) return toast('Numer musi mieć od 1 do 10 cyfr')
    if (!nick) return toast('Wpisz nick')
    DB.me = {number, nick: cleanNick(nick)}; save(); boot()
  }
}

// ── ekran główny
let tab = 'chats', homeT = null
const renderHomeSoon = () => { clearTimeout(homeT); homeT = setTimeout(renderHome, 120) }
$('#tabChats').onclick = () => { tab = 'chats'; renderHome() }
$('#tabContacts').onclick = () => { tab = 'contacts'; renderHome() }
$('#fab').onclick = () => tab === 'contacts' ? openAddContact() : openNewGroup()
$('#meChip').onclick = openProfile

function renderHome() {
  if (!DB.me) return
  $('#meAv').replaceWith(Object.assign(avatar(DB.me.nick, myUid || DB.me.number), {id: 'meAv'}))
  $('#meLbl').textContent = `${DB.me.nick} · ${DB.me.number}`
  $('#tabChats').classList.toggle('on', tab === 'chats'); $('#tabContacts').classList.toggle('on', tab === 'contacts')
  $('#chatList').classList.toggle('hidden', tab !== 'chats'); $('#contactList').classList.toggle('hidden', tab !== 'contacts')
  $('#fab').textContent = tab === 'contacts' ? '＋ Dodaj po numerze' : '＋ Nowa grupa'

  // powiadomienia (prośby, zaproszenia)
  $('#notices').replaceChildren(...notices.map(n => {
    if (n.type === 'req') return h('div', {class: 'notice'},
      h('div', {class: 't'}, `👋 ${n.nick} (nr ${n.number}) chce cię dodać`),
      h('div', {class: 'hint'}, 'Kod tej osoby: ', h('span', {class: 'kod', text: '…', 'data-kod': n.uid})),
      h('div', {class: 'row'},
        h('button', {class: 'btn sec', onclick: () => dropNotice(n.key)}, 'Odrzuć'),
        h('button', {class: 'btn', onclick: () => acceptContact(n)}, 'Dodaj')))
    if (n.type === 'inv') return h('div', {class: 'notice'},
      h('div', {class: 't'}, n.dm ? `💬 ${n.nick} zaprasza do prywatnego czatu` : `👥 ${n.nick} zaprasza do grupy „${n.name}”`),
      h('div', {class: 'row'},
        h('button', {class: 'btn sec', onclick: () => dropNotice(n.key)}, 'Odrzuć'),
        h('button', {class: 'btn', onclick: () => acceptInvite(n)}, 'Dołącz')))
  }))
  if (connProblem) $('#notices').prepend(h('div', {class: 'notice', style: 'border-color:var(--warn)'},
    h('div', {class: 't'}, connProblem === 'turn' ? '⚠️ Połączenie nie działa mimo serwera TURN' : '⚠️ Twoja sieć blokuje połączenia bezpośrednie'),
    h('div', {class: 'hint'}, connProblem === 'turn' ? 'Sprawdź dane serwera TURN.' : 'Często tak jest w sieci komórkowej. Ustaw darmowy serwer TURN – wystarczy u jednej osoby w rozmowie.'),
    h('div', {class: 'row'}, h('button', {class: 'btn', onclick: openConn}, '🛠️ Napraw połączenie'))))
  fillKods($('#notices'))

  // czaty
  const groups = Object.values(DB.groups).map(g => {
    const r = G.get(g.gid); const msgs = r ? [...r.msgs.values()].filter(m => m.t !== 'sys') : []
    const last = msgs.reduce((a, m) => (!a || m.ts > a.ts) ? m : a, null)
    return {g, r, last, sort: g.main ? Infinity : (last?.ts || g.created || 0)}
  }).sort((a, b) => b.sort - a.sort)
  $('#chatList').replaceChildren(...(groups.length ? groups.map(({g, r, last}) => {
    const online = r ? r.online.size : 0
    const prev = last ? (last.from === myUid ? 'Ty: ' : (nameOf(g, last.from) + ': ')) + (last.t === 'm' ? last.text : last.t === 'img' ? '📷 Zdjęcie' : '🎬 Filmik')
      : (online ? `${online} ${online === 1 ? 'osoba' : 'osoby'} online` : 'Brak nowych wiadomości')
    const lockTxt = !g.lock ? '🔐 Ustaw kod rozmowy' : r?.needCode() ? '🔒 Wpisz kod rozmowy' : r && !r.canTalk() ? '⏳ Czeka na potwierdzenie kodu' : null
    return h('div', {class: 'item', onclick: () => openChat(g.gid)},
      avatar(g.name, g.gid, true),
      h('div', {class: 'mid'}, h('div', {class: 't'}, (g.main ? '📌 ' : g.dm ? '' : '👥 ') + g.name), h('div', {class: 's'}, online ? h('span', {class: 'dot'}) : null, lockTxt && !last ? lockTxt : prev)),
      r?.unread ? h('div', {class: 'badge'}, r.unread) : null)
  }) : [h('div', {class: 'empty'}, h('div', {class: 'big'}, '💬'),
    Object.keys(DB.contacts).length ? 'Utwórz grupę albo napisz do kontaktu.' : 'Najpierw dodaj znajomych: wyślij im swój numer SMS-em albo wpisz ich numer w zakładce Kontakty.',
    h('button', {class: 'btn sec', style: 'max-width:280px;margin:16px auto 0', onclick: openProfile}, '📨 Wyślij mój numer SMS-em'))]))

  // kontakty
  const contacts = Object.entries(DB.contacts).sort((a, b) => a[1].nick.localeCompare(b[1].nick, 'pl'))
  $('#contactList').replaceChildren(...(contacts.length ? contacts.map(([uid, c]) =>
    h('div', {class: 'item'},
      avatar(c.nick, uid, true),
      h('div', {class: 'mid', onclick: () => openContact(uid)}, h('div', {class: 't'}, c.nick), h('div', {class: 's'}, `nr ${c.number} · `, h('span', {class: 'kod', 'data-kod': uid}, '…'))),
      h('button', {class: 'ibtn', title: 'Czat', onclick: () => openDm(uid)}, '💬'),
      h('button', {class: 'ibtn', title: 'Zadzwoń', onclick: () => startOutgoingCall(uid, false)}, '📞'),
      h('button', {class: 'ibtn', title: 'Wideo', onclick: () => startOutgoingCall(uid, true)}, '🎥'))
  ) : [h('div', {class: 'empty'}, h('div', {class: 'big'}, '📇'), 'Nie masz jeszcze kontaktów. Kliknij „Dodaj po numerze” albo wyślij komuś swój numer.')]))
  fillKods($('#contactList'))
  updateTitle()
}
function fillKods(root) { root.querySelectorAll('[data-kod]').forEach(async el => { el.textContent = await kodOf(el.dataset.kod) }) }

function acceptContact(n) {
  DB.contacts[n.uid] = {number: n.number, nick: n.nick, added: Date.now()}; save()
  inbox?.A.acc.send({number: DB.me.number, nick: DB.me.nick}, {target: n.peerId}).catch(() => toast('Nie udało się potwierdzić – poproś o ponowne dodanie'))
  dropNotice(n.key); toast(`Dodano ${n.nick}`); processOutbox()
}
async function acceptInvite(n) {
  DB.groups[n.gid] = {gid: n.gid, secret: n.secret, name: n.name, dm: n.dm ? n.uid : null, seen: {}, created: Date.now(), ttl: 0}
  save(); dropNotice(n.key)
  await startGroup(n.gid); openChat(n.gid)
}

// ── profil
function smsText() {
  const base = location.protocol.startsWith('http') ? location.origin + location.pathname : ''
  return `Hej! Dodaj mnie w groupchat 🔒\nMój numer: ${DB.me.number}\nKod: ${myKod}` + (base ? `\n${base}#add=${DB.me.number}-${normKod(myKod)}` : '')
}
function openProfile() {
  const nickIn = h('input', {class: 'in', maxlength: 32, value: DB.me.nick})
  const numIn = h('input', {class: 'in num', inputmode: 'numeric', maxlength: 10, value: DB.me.number})
  const sms = 'sms:?&body=' + encodeURIComponent(smsText())
  openSheet('Mój profil',
    h('div', {style: 'text-align:center;margin:6px 0 12px'},
      h('div', {class: 'hint'}, 'Twój numer groupchat'),
      h('div', {class: 'num', style: 'font-size:34px;font-weight:800'}, DB.me.number),
      h('div', {class: 'hint'}, 'Kod weryfikacyjny: ', h('span', {class: 'kod'}, myKod || '…'))),
    h('a', {class: 'btn', href: sms}, '📨 Wyślij mój numer SMS-em'),
    h('div', {class: 'row'},
      navigator.share ? h('button', {class: 'btn sec', onclick: () => navigator.share({text: smsText()}).catch(() => {})}, '↗ Udostępnij') : null,
      h('button', {class: 'btn sec', onclick: () => navigator.clipboard.writeText(smsText()).then(() => toast('Skopiowano')).catch(() => toast('Nie udało się skopiować'))}, '⧉ Kopiuj')),
    h('div', {class: 'hint'}, 'Kod chroni przed podszyciem się pod twój numer – znajomy, który dodaje cię z linku w SMS-ie, sprawdza go automatycznie.'),
    !location.protocol.startsWith('http') ? h('div', {class: 'warn'}, 'Aplikacja jest otwarta z pliku – link w SMS-ie zadziała dopiero, gdy wrzucisz ją na stronę https (instrukcja w README).') : null,
    h('label', {class: 'f'}, 'Nick'), nickIn,
    h('button', {class: 'btn sec', onclick: () => {
      DB.me.nick = cleanNick(nickIn.value); save(); renderHome()
      for (const r of G.values()) r.hello()
      toast('Zapisano nick')
    }}, 'Zapisz nick'),
    h('button', {class: 'btn sec', onclick: async () => {
      if (!('Notification' in window)) return toast('Ta przeglądarka nie obsługuje powiadomień')
      const p = await Notification.requestPermission(); toast(p === 'granted' ? 'Powiadomienia włączone' : 'Powiadomienia zablokowane')
    }}, '🔔 Włącz powiadomienia'),
    h('details', {style: 'margin-top:14px'},
      h('summary', {style: 'color:var(--muted);padding:8px 0'}, 'Zmień numer'),
      numIn,
      h('div', {class: 'warn'}, 'Po zmianie numeru znajomi, którzy jeszcze cię nie dodali, muszą użyć nowego. Istniejące kontakty i grupy działają dalej.'),
      h('button', {class: 'btn sec', onclick: async () => {
        const n = cleanNum(numIn.value.trim()); if (!n) return toast('Numer: od 1 do 10 cyfr')
        if (n === DB.me.number) return
        DB.me.number = n; save(); await openMyInbox(); for (const r of G.values()) r.hello(); renderHome(); closeSheet(); toast('Nowy numer: ' + n)
      }}, 'Zmień numer')),
    h('button', {class: 'btn sec', onclick: () => { closeSheet(); openConn() }}, '🛠️ Połączenie i serwer TURN'),
    h('button', {class: 'btn sec', onclick: () => { closeSheet(); openPinSettings() }}, dbKey ? '🔒 PIN aplikacji (włączony)' : '🔒 Włącz PIN aplikacji'),
    DB.settings.leftMain ? h('button', {class: 'btn sec', onclick: () => { delete DB.settings.leftMain; ensureMain(); startGroup(MAIN_GID).then(() => { closeSheet(); openChat(MAIN_GID) }) }}, '📌 Wróć do głównej grupy Bizzy Pizzy') : null,
    h('button', {class: 'btn danger', style: 'margin-top:18px', onclick: () => confirmBox('Usunąć wszystkie dane groupchat z tego telefonu? (numer, kontakty, grupy)', async () => {
      try { localStorage.removeItem(LS) } catch {}
      try { indexedDB.databases && (await indexedDB.databases()).forEach(d => d.name && indexedDB.deleteDatabase(d.name)) } catch {}
      location.hash = ''; location.reload()
    })}, 'Usuń wszystkie dane z telefonu'))
}
function openConn() {
  const cur = iceServers()
  const fromBuiltin = !DB.settings.ice?.length && !DB.settings.turn && BUILTIN_ICE.length
  const ta = h('textarea', {class: 'in', rows: 6, placeholder: 'Wklej tutaj konfigurację TURN z panelu (iceServers)…', style: 'font-family:ui-monospace,monospace;font-size:12.5px'})
  ta.value = DB.settings.ice?.length ? JSON.stringify(DB.settings.ice, null, 1) : ''
  const preview = h('div', {class: 'hint'})
  const showPrev = () => {
    const ice = parseIce(ta.value)
    preview.textContent = ta.value.trim() ? (ice.length ? `Rozpoznano: ${ice.reduce((a, x) => a + x.urls.length, 0)} adresów TURN` + (ice.some(x => x.username) ? ', z loginem' : ', BEZ loginu/hasła!') : '❌ Nie rozpoznano adresów turn:…') : ''
  }
  ta.oninput = showPrev
  const res = h('div', {class: 'hint', style: 'min-height:20px'})
  const diag = h('div', {class: 'hint'})
  const relIn = h('input', {class: 'in', value: DB.settings.relays || '', placeholder: 'domyślne publiczne relaye Nostr'})
  const runDiag = async () => {
    diag.textContent = 'Sprawdzam…'
    const socks = Object.values(getRelaySockets?.() || {}); const up = socks.filter(w => w?.readyState === 1).length
    const stun = await testStun()
    const ice = iceServers(); const turn = ice.length ? await testIce(ice) : null
    diag.replaceChildren(
      h('div', {}, `${up ? '✅' : '❌'} Serwery sygnalizacji: ${up}/${socks.length} połączonych`),
      h('div', {}, `${stun ? '✅' : '⚠️'} Publiczny adres (STUN): ${stun ? 'wykryty' : 'sieć blokuje UDP'}`),
      h('div', {}, turn === null ? '⚠️ Serwer TURN: nie ustawiony' : `${turn ? '✅' : '❌'} Serwer TURN: ${turn ? 'działa' : 'nie odpowiada / złe dane'}${fromBuiltin ? ' (wbudowany)' : ''}`))
  }
  openSheet('🛠️ Połączenie',
    h('div', {class: 'hint'}, 'W sieciach komórkowych telefony często nie mogą połączyć się bezpośrednio. Wtedy dane (nadal zaszyfrowane) idą przez serwer TURN. Wystarczy, że ustawi go jedna osoba w rozmowie.'),
    h('button', {class: 'btn sec', onclick: runDiag}, '🩺 Sprawdź moje połączenie'), diag,
    h('label', {class: 'f'}, 'Serwer TURN – jak ustawić (za darmo):'),
    h('div', {class: 'hint', style: 'margin:0'},
      '1. Załóż darmowe konto: ', h('a', {href: 'https://dashboard.metered.ca/signup', target: '_blank', rel: 'noopener'}, 'dashboard.metered.ca/signup'), ' (20 GB/mies.)', h('br'),
      '2. W panelu: TURN Server → utwórz dane logowania (Credentials) → pokaż „ICE Servers Array” i skopiuj całość', h('br'),
      '3. Wklej poniżej → Testuj → Zapisz'),
    h('div', {class: 'hint'}, 'Inne darmowe: expressturn.com (1 TB/mies., port 3478). Wklej adres turn:…, login i hasło w dowolnej formie.'),
    ta, preview,
    h('div', {class: 'row'},
      h('button', {class: 'btn sec', onclick: async () => {
        const ice = parseIce(ta.value); if (!ice.length) { res.textContent = '❌ Brak poprawnych adresów turn:'; return }
        res.textContent = 'Testuję serwer TURN…'; res.textContent = (await testIce(ice)) ? '✅ Serwer TURN działa' : '❌ Serwer nie odpowiada – sprawdź login/hasło albo adres'
      }}, '🧪 Testuj'),
      h('button', {class: 'btn', onclick: () => {
        const ice = parseIce(ta.value)
        if (ta.value.trim() && !ice.length) { res.textContent = '❌ Nie rozpoznano konfiguracji'; return }
        DB.settings.ice = ice; delete DB.settings.turn; delete DB.settings.turnUser; delete DB.settings.turnPass
        DB.settings.relays = relIn.value.trim(); save(); toast('Zapisano – uruchamiam ponownie'); setTimeout(() => location.reload(), 800)
      }}, '💾 Zapisz')),
    res,
    fromBuiltin ? h('div', {class: 'hint'}, 'Teraz używany jest serwer TURN wbudowany w aplikację. Wklejenie własnego go zastąpi.') : null,
    h('details', {style: 'margin-top:12px'}, h('summary', {style: 'color:var(--muted);padding:8px 0'}, 'Zaawansowane: własne relaye Nostr'), relIn))
  showPrev()
}
function inviteByLink(g) {
  const base = location.protocol.startsWith('http') ? location.origin + location.pathname : ''
  const link = `${base}#join=${g.gid}.${g.secret}.${encodeURIComponent(g.name)}`
  const text = `Dołącz do grupy „${g.name}” w groupchat 🔒\n${link}\nKod rozmowy podam Ci przez telefon.`
  openSheet('Zaproś do „' + g.name + '”',
    h('div', {class: 'hint'}, 'Link wpuszcza do grupy, ale bez kodu rozmowy nikt nic nie odczyta. Po wysłaniu zadzwoń i podyktuj kod.'),
    h('a', {class: 'btn', href: 'sms:?&body=' + encodeURIComponent(text)}, '📨 Wyślij SMS-em'),
    h('div', {class: 'row'},
      navigator.share ? h('button', {class: 'btn sec', onclick: () => navigator.share({text}).catch(() => {})}, '↗ Udostępnij') : null,
      h('button', {class: 'btn sec', onclick: () => navigator.clipboard.writeText(text).then(() => toast('Skopiowano')).catch(() => toast('Nie udało się skopiować'))}, '⧉ Kopiuj')))
}
function openPinSettings() {
  const a = h('input', {class: 'in num', type: 'password', inputmode: 'numeric', autocomplete: 'new-password', placeholder: 'min. 6 cyfr'})
  const b = h('input', {class: 'in num', type: 'password', inputmode: 'numeric', autocomplete: 'new-password', placeholder: 'powtórz PIN'})
  const wipe = h('input', {type: 'checkbox', checked: lockInfo()?.wipe ?? true})
  const msg = h('div', {class: 'warn', style: 'min-height:0'})
  const go = h('button', {class: 'btn'}, dbKey ? 'Zmień PIN' : 'Włącz PIN')
  go.onclick = async () => {
    if (!/^\d{6,12}$/.test(a.value)) { msg.textContent = 'PIN: od 6 do 12 cyfr'; return }
    if (a.value !== b.value) { msg.textContent = 'PIN-y się różnią'; return }
    if (/^(\d)\1+$/.test(a.value) || '0123456789012'.includes(a.value) || '9876543210987'.includes(a.value)) { msg.textContent = 'Za prosty PIN'; return }
    go.disabled = true; msg.textContent = 'Szyfruję dane…'
    try { await enablePin(a.value, wipe.checked); closeSheet(); toast('🔒 PIN ustawiony – dane na telefonie są zaszyfrowane') }
    catch (e) { msg.textContent = 'Błąd: ' + e.message; go.disabled = false }
  }
  openSheet('🔒 PIN aplikacji',
    h('div', {class: 'hint'}, 'Z PIN-em wszystko, co groupchat zapisuje na telefonie (historia, zdjęcia, filmiki, kontakty, kody rozmów), jest zaszyfrowane kluczem z PIN-u. Inny program ani osoba, która skopiuje pamięć telefonu, niczego nie odczyta. Aplikacja blokuje się po 2 min w tle.'),
    h('div', {class: 'warn'}, 'Zapomniany PIN = utracone dane (nie da się ich odzyskać).'),
    h('label', {class: 'f'}, dbKey ? 'Nowy PIN' : 'PIN'), a, h('div', {style: 'height:8px'}), b,
    h('label', {class: 'cb'}, wipe, 'Usuń wszystkie dane po 10 błędnych PIN-ach'),
    msg, go,
    dbKey ? h('button', {class: 'btn sec', onclick: () => location.reload()}, '🔐 Zablokuj teraz') : null,
    dbKey ? h('button', {class: 'btn danger', onclick: () => confirmBox('Wyłączyć PIN? Dane na telefonie będą chronione tylko kluczem urządzenia.', async () => { await disablePin(); toast('PIN wyłączony') })}, 'Wyłącz PIN') : null)
}
function confirmBox(text, onYes) {
  openSheet('Potwierdź', h('div', {style: 'margin:6px 0 6px'}, text),
    h('div', {class: 'row'}, h('button', {class: 'btn sec', onclick: closeSheet}, 'Anuluj'), h('button', {class: 'btn', style: 'background:var(--danger);color:#fff', onclick: () => { closeSheet(); onYes() }}, 'Tak')))
}

// ── dodawanie kontaktu po numerze
let addFlow = null
function openAddContact(prefNum = '', prefKod = '', auto = false) {
  const numIn = h('input', {class: 'in num', inputmode: 'numeric', maxlength: 10, value: prefNum, placeholder: 'np. 482133'})
  const kodIn = h('input', {class: 'in num', maxlength: 9, value: prefKod ? prefKod.slice(0, 4) + '-' + prefKod.slice(4) : '', placeholder: 'opcjonalnie, np. K7QF-2MXA'})
  const status = h('div', {class: 'hint', style: 'min-height:20px'})
  const list = h('div')
  const go = h('button', {class: 'btn'}, 'Szukaj')
  openSheet('Dodaj kontakt', h('label', {class: 'f'}, 'Numer groupchat znajomego'), numIn,
    h('label', {class: 'f'}, 'Kod z SMS-a (zalecane)'), kodIn, go, status, list,
    h('div', {class: 'hint', style: 'margin-top:14px'}, 'Znajomy musi mieć teraz otwartą aplikację. Nie znasz numeru? Wyślij swój: Profil → „Wyślij mój numer SMS-em”.'))
  const flow = addFlow = {onAccepted: null}
  go.onclick = async () => {
    const num = cleanNum(numIn.value.trim()); const kod = normKod(kodIn.value)
    if (!num) return toast('Numer: od 1 do 10 cyfr')
    if (num === DB.me.number) return toast('To twój własny numer 🙂')
    go.disabled = true; list.replaceChildren(); status.textContent = `Szukam numeru ${num}…`
    const v = visit(num); v.busy++
    try {
      let owners = await waitOwners(v, null, 20000)
      if (addFlow !== flow) return
      if (!owners.length) { status.textContent = `Nikt z numerem ${num} nie jest teraz online. Poproś znajomego, żeby otworzył groupchat, i spróbuj ponownie.`; return }
      const withKod = await Promise.all(owners.map(async o => ({...o, kod: await kodOf(o.userId)})))
      let pick = kod.length === 8 ? withKod.filter(o => normKod(o.kod) === kod) : withKod
      if (kod.length === 8 && !pick.length) { status.textContent = 'Znaleziono numer, ale kod się nie zgadza! Możliwe podszycie – sprawdź kod u znajomego.'; return }
      status.textContent = pick.length > 1 ? 'Kilka osób używa tego numeru – wybierz po kodzie:' : (kod.length === 8 ? '✅ Kod zgodny.' : 'Znaleziono. Porównaj kod ze znajomym:')
      const send = o => {
        if (DB.contacts[o.userId]) { status.textContent = `${o.nick} jest już w kontaktach.`; return }
        sentReqs.set(num, o.userId)
        v.A.req.send({number: DB.me.number, nick: DB.me.nick}, {target: o.peerId}).catch(() => {})
        list.replaceChildren(); status.textContent = `Wysłano prośbę do ${o.nick}. Czekam, aż ją przyjmie…`
        flow.onAccepted = uid => { if (uid !== o.userId) return; status.textContent = `✅ ${o.nick} dodany(-a) do kontaktów!`; setTimeout(() => { if (addFlow === flow) { closeSheet(); tab = 'contacts'; renderHome() } }, 1200) }
      }
      if (pick.length === 1 && kod.length === 8 && auto) return send(pick[0])
      list.replaceChildren(...pick.map(o => h('div', {class: 'item', style: 'padding:10px 0'},
        avatar(o.nick, o.userId, true),
        h('div', {class: 'mid'}, h('div', {class: 't'}, o.nick), h('div', {class: 's'}, 'Kod: ', h('span', {class: 'kod'}, o.kod))),
        h('button', {class: 'btn', style: 'width:auto;margin:0', onclick: () => send(o)}, 'Dodaj'))))
    } finally { v.busy--; go.disabled = false }
  }
  if (auto && prefNum) go.click()
}

// ── kontakt
function openContact(uid) {
  const c = DB.contacts[uid]; if (!c) return
  const kodEl = h('span', {class: 'kod'}, '…'); kodOf(uid).then(k => { kodEl.textContent = k })
  openSheet(c.nick,
    h('div', {class: 'hint'}, `Numer: ${c.number} · Kod: `, kodEl),
    h('div', {class: 'hint'}, 'Porównajcie kody przy spotkaniu – jeśli się zgadzają, rozmawiasz na pewno z tą osobą.'),
    h('button', {class: 'btn', onclick: () => { closeSheet(); openDm(uid) }}, '💬 Napisz'),
    h('div', {class: 'row'},
      h('button', {class: 'btn sec', onclick: () => { closeSheet(); startOutgoingCall(uid, false) }}, '📞 Zadzwoń'),
      h('button', {class: 'btn sec', onclick: () => { closeSheet(); startOutgoingCall(uid, true) }}, '🎥 Wideo')),
    h('button', {class: 'btn danger', onclick: () => confirmBox(`Usunąć ${c.nick} z kontaktów?`, () => { delete DB.contacts[uid]; save(); renderHome() })}, 'Usuń kontakt'))
}

// ── grupy
function newGroupRecord(name, dm = null) {
  const gid = hex(rnd(16))
  DB.groups[gid] = {gid, secret: b64(rnd(24)), name, dm, seen: {}, created: Date.now(), ttl: 0}
  save(); return gid
}
async function openDm(uid) {
  const ex = Object.values(DB.groups).find(g => g.dm === uid)
  if (ex) return openChat(ex.gid)
  const gid = newGroupRecord(DB.contacts[uid].nick, uid)
  await startGroup(gid); queueInvite(uid, gid); openChat(gid)
}
function contactChecks(exclude = new Set()) {
  const items = Object.entries(DB.contacts).filter(([uid]) => !exclude.has(uid)).map(([uid, c]) => {
    const cb = h('input', {type: 'checkbox', value: uid})
    return {cb, el: h('label', {class: 'check'}, cb, avatar(c.nick, uid), h('div', {}, h('div', {}, c.nick), h('div', {class: 'hint', style: 'margin:0'}, 'nr ' + c.number)))}
  })
  return {els: items.map(i => i.el), picked: () => items.filter(i => i.cb.checked).map(i => i.cb.value)}
}
function openNewGroup() {
  const nameIn = h('input', {class: 'in', maxlength: 40, placeholder: 'np. Ekipa z pracy'})
  const ch = contactChecks()
  openSheet('Nowa grupa', h('label', {class: 'f'}, 'Nazwa grupy'), nameIn,
    h('label', {class: 'f'}, 'Zaproś z kontaktów'),
    ...(ch.els.length ? ch.els : [h('div', {class: 'hint'}, 'Brak kontaktów – możesz założyć grupę i zaprosić ludzi później.')]),
    h('button', {class: 'btn', onclick: async () => {
      const name = nameIn.value.trim(); if (!name) return toast('Podaj nazwę grupy')
      const gid = newGroupRecord(cleanNick(name).slice(0, 40))
      await startGroup(gid); for (const uid of ch.picked()) queueInvite(uid, gid)
      closeSheet(); openChat(gid)
    }}, 'Utwórz grupę'))
}

// ── czat
let typingSentAt = 0
async function openChat(gid) {
  const r = await startGroup(gid)
  openGid = gid; r.unread = 0; updateTitle()
  show('#chat'); renderChatHead()
  const box = $('#msgs'); box.replaceChildren()
  for (const m of [...r.msgs.values()].sort((a, b) => a.ts - b.ts)) box.append(msgEl(r, m))
  renderTyping(); renderLock(); scrollDown(true)
}
function closeChat() { openGid = null; show('#home'); renderHome() }
$('#chatBack').onclick = closeChat
window.addEventListener('popstate', () => { if (openGid) closeChat() })

function renderChatHead() {
  const g = DB.groups[openGid], r = G.get(openGid); if (!g || !r) return
  $('#chatName').textContent = g.name
  const on = [...r.online.keys()].map(u => nameOf(g, u))
  const pend = DB.outbox.filter(i => i.gid === g.gid).length
  const lk = !g.lock ? '🔓 bez kodu · ' : r.needCode() ? '🔒 wpisz kod · ' : !r.canTalk() ? '⏳ czeka na potwierdzenie · ' : '🔒 '
  $('#chatSub').textContent = lk + (on.length ? `🟢 online: ${on.join(', ')}` : 'nikt poza tobą nie jest online') +
    (g.ttl ? ` · ⏱ ${ttlLabel(g.ttl)}` : '') + (pend ? ` · ✉ ${pend} zaproszeń czeka` : '')
  $('#chatCall').classList.toggle('hidden', !!g.dm && !DB.contacts[g.dm])
  renderCallBanner()
}
function refreshGroup(r) { if (openGid === r.gid) { renderChatHead(); renderLock() } renderHomeSoon() }
const ttlLabel = s => s >= 86400 ? `${s / 86400} d` : s >= 3600 ? `${s / 3600} h` : `${s / 60} min`

$('#chatCall').onclick = () => {
  const g = DB.groups[openGid]; if (!g) return
  if (!g.dm) {
    const r = G.get(openGid); const n = r ? r.online.size : 0
    return openSheet('Rozmowa grupowa – ' + g.name,
      h('div', {class: 'hint'}, `Online: ${n} ${n === 1 ? 'osoba' : 'osób'}. Każdy w grupie dostanie zaproszenie i może dołączyć także później. Najlepiej działa do 6 osób.`),
      h('button', {class: 'btn', onclick: () => { closeSheet(); startGroupCall(openGid, false) }}, '📞 Rozmowa głosowa'),
      h('button', {class: 'btn sec', onclick: () => { closeSheet(); startGroupCall(openGid, true) }}, '🎥 Rozmowa wideo'))
  }
  openSheet('Zadzwoń do ' + g.name,
    h('button', {class: 'btn', onclick: () => { closeSheet(); startOutgoingCall(g.dm, false) }}, '📞 Połączenie głosowe'),
    h('button', {class: 'btn sec', onclick: () => { closeSheet(); startOutgoingCall(g.dm, true) }}, '🎥 Połączenie wideo'))
}
$('#chatMembers').onclick = () => {
  const g = DB.groups[openGid], r = G.get(openGid); if (!g) return
  const members = Object.entries(g.seen).filter(([u]) => u !== myUid)
  const inGroup = new Set(members.map(([u]) => u))
  const ch = contactChecks(new Set([...inGroup, ...(g.dm ? [g.dm] : [])]))
  const ttlSel = h('select', {class: 'in'}, ...[[0, 'Wyłączone'], [300, '5 minut'], [3600, '1 godzina'], [86400, '1 dzień'], [604800, '7 dni']]
    .map(([v, l]) => h('option', {value: v, selected: Number(g.ttl || 0) === v}, l)))
  ttlSel.onchange = () => { g.ttl = Number(ttlSel.value); save(); renderChatHead(); toast('Znikające wiadomości: ' + ttlSel.selectedOptions[0].text) }
  openSheet(g.name,
    h('label', {class: 'f'}, 'Osoby w grupie'),
    h('div', {class: 'check'}, avatar(DB.me.nick, myUid), h('div', {}, `${DB.me.nick} (ty)`)),
    ...members.map(([u, s]) => h('div', {class: 'check'}, avatar(s.nick, u),
      h('div', {style: 'flex:1'}, h('div', {}, nameOf(g, u), DB.contacts[u] ? ' ✓' : ''), h('div', {class: 'hint', style: 'margin:0'}, (r?.online.has(u) ? '🟢 online' : 'offline') + (s.number ? ' · nr ' + s.number : ''))))),
    g.dm ? null : h('label', {class: 'f'}, 'Zaproś kolejne osoby'),
    g.dm ? null : (ch.els.length ? ch.els : [h('div', {class: 'hint'}, 'Wszystkie twoje kontakty już tu są (albo nie masz kontaktów).')]),
    g.dm ? null : h('button', {class: 'btn', onclick: () => inviteByLink(g)}, '📨 Zaproś linkiem (SMS) – dowolną osobę'),
    g.dm || !ch.els.length ? null : h('button', {class: 'btn sec', onclick: () => { const p = ch.picked(); p.forEach(u => queueInvite(u, g.gid)); closeSheet(); renderChatHead(); toast(p.length ? 'Zaproszenia zostaną dostarczone, gdy osoby będą online' : 'Nikogo nie zaznaczono') }}, 'Wyślij zaproszenia'),
    h('label', {class: 'f'}, '⏱ Znikające wiadomości (dla wysyłanych przez ciebie)'), ttlSel,
    h('div', {class: 'hint'}, 'Wiadomości, zdjęcia i filmiki zapisują się na tym telefonie (zaszyfrowane). Pod swoją wiadomością możesz wybrać „⏱ Ma zniknąć?” – zniknie u wszystkich po 10 minutach.'),
    h('button', {class: 'btn sec', style: 'margin-top:16px', onclick: () => confirmBox(`Usunąć historię „${g.name}” z tego telefonu?`, async () => {
      await histClear(g.gid); for (const m of r?.msgs.values() || []) if (m.url) URL.revokeObjectURL(m.url); r?.msgs.clear(); openChat(g.gid)
    })}, '🗑️ Wyczyść historię na tym telefonie'),
    h('button', {class: 'btn danger', onclick: () => confirmBox(`Opuścić „${g.name}”?`, () => {
      r?.room.leave().catch(() => {}); for (const m of r?.msgs.values() || []) if (m.url) URL.revokeObjectURL(m.url)
      histClear(g.gid); if (g.main) DB.settings.leftMain = true
      G.delete(g.gid); delete DB.groups[g.gid]; DB.outbox = DB.outbox.filter(i => i.gid !== g.gid); save(); closeChat()
    })}, 'Opuść grupę'))
}


// ── kod rozmowy: kreator w czacie
function renderLock() {
  const r = G.get(openGid), g = DB.groups[openGid]; if (!r || !g) return
  const bar = $('#lockBar')
  const mode = !g.lock ? 'wizard' : r.needCode() ? 'entry' : !r.canTalk() ? 'wait' : 'ok'
  const talk = mode === 'ok'
  $('#composer').classList.toggle('hidden', !talk); $('#typing').classList.toggle('hidden', !talk)
  bar.classList.toggle('hidden', talk)
  renderChatHead()
  if (talk) { bar.replaceChildren(); bar.dataset.state = ''; return }
  const state = mode === 'wizard' ? 'wizard' : mode + '|' + g.lock.epoch + '|' + (mode === 'entry' ? r.pending.length : '')
  if (bar.dataset.state === state) return
  const keep = bar.querySelector('.codeboxes') && mode === 'entry' && bar.dataset.state?.startsWith('entry') ? [...bar.querySelectorAll('.codebox')].map(x => x.value).join('') : ''
  bar.dataset.state = state
  const dmContact = g.dm && DB.contacts[g.dm] ? g.dm : null
  const callBtns = () => dmContact ? h('div', {class: 'row'},
    h('button', {class: 'btn sec', onclick: () => startOutgoingCall(dmContact, false)}, '📞 Zadzwoń w groupchat'),
    h('button', {class: 'btn sec', onclick: () => startOutgoingCall(dmContact, true)}, '🎥 Wideo')) : null
  const rememberBox = (on = true) => { const cb = h('input', {type: 'checkbox', checked: on}); return {cb, el: h('label', {class: 'cb'}, cb, 'Pamiętaj kod na tym telefonie')} }
  const step = (n, title, ...body) => h('div', {class: 'step on'}, h('div', {class: 'n'}, n), h('div', {class: 'b'}, h('b', {}, title), ...body))
  const sub = t => h('div', {class: 'hint', style: 'margin:2px 0 0'}, t)

  if (mode === 'wizard') {
    // 1. zadzwoń → 2. generuj (możesz poprawić cyfry) → 3. podyktuj → 4. zatwierdź → rozmówca wpisuje i zatwierdza
    const boxes = codeBoxes(genCode())
    const rem = rememberBox()
    const err = h('div', {class: 'warn', style: 'min-height:0'})
    const go = h('button', {class: 'btn'}, '✅ Podyktowałem – zatwierdź kod')
    go.onclick = async () => {
      const c = boxes.get(); const p = codeProblem(c); if (p) { err.textContent = p; boxes.focus(); return }
      go.disabled = true; go.textContent = 'Szyfruję…'; err.textContent = ''
      try { await r.setCode(c, rem.cb.checked); renderLock() }
      catch (e) { err.textContent = e.message; go.disabled = false; go.textContent = '✅ Podyktowałem – zatwierdź kod' }
    }
    bar.replaceChildren(
      h('h3', {}, '🔐 Zabezpiecz rozmowę kodem'),
      h('div', {class: 'hint', style: 'margin:0 0 6px'}, 'Rozmowa ruszy dopiero, gdy obie strony zatwierdzą ten sam kod.'),
      step('1', 'Zadzwoń do rozmówcy', sub('Zwykłym telefonem' + (dmContact ? ' albo przez groupchat (porównajcie kod połączenia na ekranie).' : '.')), callBtns()),
      step('2', 'Kod rozmowy', sub('Wylosowany automatycznie – możesz poprawić dowolną cyfrę.'), boxes.el,
        h('button', {class: 'btn sec', onclick: () => { boxes.set(genCode()); err.textContent = '' }}, '🔁 Wylosuj inny')),
      step('3', 'Podyktuj kod rozmówcy', sub('Na głos, w trakcie rozmowy. Nie wysyłaj go SMS-em ani w tym czacie.')),
      step('4', 'Zatwierdź', sub('Rozmówca wpisze kod u siebie i zatwierdzi. Wtedy zaczniecie rozmawiać.'), rem.el, err, go),
      h('div', {class: 'hint'}, 'Rozmówca już podyktował ci swój kod? Gdy będzie online, pojawi się tu pole do jego wpisania.'))
    return
  }

  if (mode === 'entry') {
    const rem = rememberBox()
    const msg = h('div', {class: 'hint', style: 'min-height:18px'}, r.entryMsg || '')
    r.entryMsg = ''
    const ok = h('button', {class: 'btn'}, '✅ Zatwierdź kod')
    const boxes = codeBoxes(keep, {onEnter: () => ok.click()})
    ok.onclick = async () => {
      const c = boxes.get(); if (c.length !== 12) { msg.textContent = 'Kod ma 12 cyfr – uzupełnij pola'; boxes.focus(); return }
      ok.disabled = true; msg.textContent = 'Sprawdzam kod…'
      const good = await r.unlock(c, rem.cb.checked)
      ok.disabled = false
      if (good === 'old') { r.entryMsg = '⚠️ To poprzedni kod – rozmówca go poprawił. Poproś o nowy i popraw cyfry.'; $('#lockBar').dataset.state += '|x'; renderLock(); return }
      if (good) { toast('✅ Kod zatwierdzony'); renderLock(); scrollDown(true) }
      else { msg.textContent = '❌ Kod się nie zgadza. Popraw cyfry (dotknij pola) albo poproś o ponowne podyktowanie.'; }
    }
    bar.replaceChildren(
      h('h3', {}, '🔒 Wpisz kod rozmowy'),
      h('div', {class: 'hint', style: 'margin:0 0 8px'}, `Kod ustawił(a): ${g.lock.nick}. Zadzwoń do tej osoby i poproś, żeby podyktowała ci kod. Każdą cyfrę możesz poprawić.`),
      callBtns(), boxes.el,
      h('button', {class: 'btn sec', onclick: () => { boxes.set(''); boxes.focus(); msg.textContent = '' }}, '⌫ Wyczyść'),
      rem.el, ok, msg,
      r.pending.length ? h('div', {class: 'warn'}, `🔒 ${r.pending.length} zaszyfrowanych wiadomości czeka na kod`) : null)
    setTimeout(() => boxes.focus(), 50)
    return
  }

  // mode === 'wait': ja mam kod, czekam aż rozmówca go wpisze i zatwierdzi
  const cur = g.codes?.[g.lock.epoch] || r.memCode || ''
  const boxes = codeBoxes(cur, {readonly: true})
  const fixArea = h('div')
  const openFix = () => {
    const fb = codeBoxes(cur || genCode())
    const err = h('div', {class: 'warn', style: 'min-height:0'})
    const save1 = h('button', {class: 'btn'}, '✅ Zatwierdź poprawiony kod')
    save1.onclick = async () => {
      const c = fb.get(); const p = codeProblem(c); if (p) { err.textContent = p; return }
      if (c === cur) { err.textContent = 'To ten sam kod – zmień cyfry albo wylosuj nowy'; return }
      save1.disabled = true
      try { await r.setCode(c, !!g.codes || !r.memCode); bar.dataset.state = ''; renderLock(); toast('Kod poprawiony – podyktuj go jeszcze raz') }
      catch (e) { err.textContent = e.message; save1.disabled = false }
    }
    fixArea.replaceChildren(h('label', {class: 'f'}, 'Popraw kod (zmień cyfry) i podyktuj ponownie'), fb.el,
      h('button', {class: 'btn sec', onclick: () => fb.set(genCode())}, '🔁 Wylosuj nowy'), err, save1)
    fb.focus()
  }
  bar.replaceChildren(
    h('h3', {}, '⏳ Czekam na potwierdzenie kodu'),
    h('div', {class: 'hint', style: 'margin:0 0 6px'}, `Podyktuj ten kod rozmówcy${dmContact ? ' (' + DB.contacts[dmContact].nick + ')' : ''}. Rozmowa ruszy, gdy wpisze go u siebie i zatwierdzi. Pomyliłeś się? Popraw kod.`),
    cur ? boxes.el : h('div', {class: 'hint'}, 'Kod nie jest zapamiętany na tym telefonie – ustaw nowy.'),
    callBtns(),
    h('button', {class: 'btn sec', onclick: openFix}, '✏️ Popraw kod'),
    fixArea)
}

$('#chatLock').onclick = () => {
  const r = G.get(openGid), g = DB.groups[openGid]; if (!r || !g) return
  if (!r.canTalk()) { bar0(); return }
  function bar0() { renderLock(); $('#lockBar').scrollIntoView(); toast(!g.lock ? 'Wygeneruj kod i podyktuj go rozmówcy' : r.needCode() ? 'Wpisz kod od rozmówcy' : 'Czekam, aż rozmówca zatwierdzi kod') }
  const known = g.codes?.[g.lock.epoch] || r.memCode
  const fb = codeBoxes(genCode())
  const err = h('div', {class: 'warn', style: 'min-height:0'})
  const rem = h('input', {type: 'checkbox', checked: !!g.codes})
  const members = r.confirmedBy().map(u => nameOf(g, u))
  const notYet = Object.keys(g.seen).filter(u => u !== myUid && !r.confirmedBy().includes(u)).map(u => nameOf(g, u))
  openSheet('🔐 Kod rozmowy',
    h('div', {class: 'hint'}, `Rozmowa jest szyfrowana kodem (ustawił(a): ${g.lock.nick}).`),
    known ? codeBoxes(known, {readonly: true}).el : h('div', {class: 'hint'}, 'Kod nie jest zapamiętany na tym telefonie.'),
    h('div', {class: 'hint'}, '✅ Potwierdzili kod: ' + (members.join(', ') || '—')),
    notYet.length ? h('div', {class: 'warn'}, '⏳ Bez kodu (nie odczytają rozmowy): ' + notYet.join(', ')) : null,
    h('label', {class: 'f'}, '✏️ Popraw / zmień kod'),
    h('div', {class: 'hint', style: 'margin:0'}, 'Zadzwoń, podyktuj nowy kod i zatwierdź. Wszyscy będą musieli wpisać go ponownie.'),
    fb.el,
    h('button', {class: 'btn sec', onclick: () => fb.set(genCode())}, '🔁 Wylosuj inny'),
    h('label', {class: 'cb'}, rem, 'Pamiętaj kod na tym telefonie'), err,
    h('button', {class: 'btn', onclick: async e => {
      const c = fb.get(); const p = codeProblem(c); if (p) { err.textContent = p; return }
      e.target.disabled = true
      try { await r.setCode(c, rem.checked); closeSheet(); renderLock(); toast('Nowy kod ustawiony – podyktuj go rozmówcom') }
      catch (er) { err.textContent = er.message; e.target.disabled = false }
    }}, '✅ Podyktowałem – zatwierdź nowy kod'),
    known && g.codes ? h('button', {class: 'btn danger', onclick: () => { r.memCode = known; delete g.codes; save(); closeSheet(); toast('Kod nie będzie pamiętany po zamknięciu aplikacji') }}, 'Nie pamiętaj kodu na tym telefonie') : null)
}


function linkify(text) {
  const out = []; const re = /\bhttps?:\/\/[^\s<>"']+/g; let last = 0, m
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index))
    out.push(h('a', {href: m[0], target: '_blank', rel: 'noopener noreferrer'}, m[0])); last = m.index + m[0].length
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}
function msgEl(r, m) {
  const g = DB.groups[r.gid]
  if (m.t === 'sys') return h('div', {class: 'msg sys', 'data-mid': m.id, 'data-ts': m.ts}, m.text)
  const mine = m.from === myUid
  const who = !mine && !g.dm ? h('div', {class: 'who', style: `color:hsl(${hue(m.from)} 65% 68%)`}, nameOf(g, m.from)) : null
  let body
  if (m.t === 'm') body = linkify(m.text)
  else if (m.t === 'img') body = h('img', {src: m.url, alt: 'zdjęcie', loading: 'lazy', onclick: () => { $('#viewerImg').src = m.url; $('#viewer').classList.remove('hidden') }})
  else body = h('video', {src: m.url, controls: true, playsinline: true, preload: 'metadata'})
  const prog = mine && m.t !== 'm' && m.sending !== undefined && m.sending < 1 && r.online.size ? h('div', {class: 'prog'}, h('i')) : null
  const meta = h('div', {class: 'meta'}, hhmm(m.ts) + (m.exp ? ` · ⏱ zniknie o ${hhmm(m.exp)}` : ''))
  let ask = null
  if (mine && !m.exp && !m.keep) {
    ask = h('div', {class: 'ask'})
    const closed = () => ask.replaceChildren(h('button', {class: 'lnk', onclick: open}, '⏱ Ma zniknąć?'))
    const open = () => ask.replaceChildren(h('span', {}, 'Zniknąć za 10 min u wszystkich? '),
      h('button', {class: 'lnk yes', onclick: () => expireMsg(r, m)}, 'Tak'), ' · ',
      h('button', {class: 'lnk', onclick: () => { m.keep = true; histPut(r.gid, m); ask.remove() }}, 'Nie'))
    closed()
  }
  return h('div', {class: 'msg' + (mine ? ' mine' : '') + (m.exp ? ' expiring' : ''), 'data-mid': m.id, 'data-ts': m.ts}, who, body, prog, meta, ask)
}
function refreshMsgEl(r, m) {
  const old = document.querySelector(`[data-mid="${CSS.escape(m.id)}"]`)
  if (old && openGid === r.gid) old.replaceWith(msgEl(r, m))
}
async function expireMsg(r, m) {
  m.x = Date.now() + 10 * 60e3; m.exp = m.x
  histPut(r.gid, m); refreshMsgEl(r, m)
  r.A.exp.send(await r.seal({id: m.id, x: m.x})).catch(() => {})
  toast('Wiadomość zniknie u wszystkich za 10 minut')
}
function insertMsgEl(m) {
  const r = G.get(openGid); if (!r) return
  const box = $('#msgs'); const atBottom = nearBottom()
  const el = msgEl(r, m)
  const after = [...box.children].find(c => Number(c.dataset.ts) > m.ts)
  after ? box.insertBefore(el, after) : box.append(el)
  if (atBottom || m.from === myUid) scrollDown()
}
const nearBottom = () => { const s = $('#msgScroll'); return s.scrollHeight - s.scrollTop - s.clientHeight < 140 }
const scrollDown = (now) => requestAnimationFrame(() => { const s = $('#msgScroll'); s.scrollTop = s.scrollHeight; if (now) setTimeout(() => { s.scrollTop = s.scrollHeight }, 300) })
$('#viewer').onclick = () => $('#viewer').classList.add('hidden')

function renderTyping() {
  const r = G.get(openGid); const g = DB.groups[openGid]; if (!r) return
  const parts = []
  for (const [u, p] of r.prog) parts.push(`${nameOf(g, u)} wysyła plik… ${Math.round(p * 100)}%`)
  const typers = [...r.typing.keys()].map(u => nameOf(g, u))
  if (typers.length) parts.push(`${typers.join(', ')} ${typers.length > 1 ? 'piszą' : 'pisze'}…`)
  $('#typing').textContent = parts.join(' · ')
}

const txt = $('#txt')
txt.addEventListener('input', () => {
  txt.style.height = 'auto'; txt.style.height = Math.min(130, txt.scrollHeight) + 'px'
  const r = G.get(openGid)
  if (r && Date.now() - typingSentAt > 2500 && txt.value) { typingSentAt = Date.now(); r.A.typ.send(1).catch(() => {}) }
})
txt.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey && !matchMedia('(pointer:coarse)').matches) { e.preventDefault(); doSend() }
})
$('#sendBtn').onclick = doSend
function doSend() {
  const r = G.get(openGid); const text = txt.value.trim(); if (!r || !text) return
  txt.value = ''; txt.style.height = 'auto'; sendText(r, text); txt.focus()
}
$('#attach').onclick = () => openSheet('Wyślij',
  h('button', {class: 'opt', onclick: () => { closeSheet(); $('#fPhoto').click() }}, h('span', {class: 'e'}, '📷'), 'Zrób zdjęcie'),
  h('button', {class: 'opt', onclick: () => { closeSheet(); $('#fVideo').click() }}, h('span', {class: 'e'}, '🎬'), `Nagraj filmik (maks. ${MAX_VIDEO_S} s)`),
  h('button', {class: 'opt', onclick: () => { closeSheet(); $('#fGallery').click() }}, h('span', {class: 'e'}, '🖼️'), 'Z galerii (zdjęcie lub filmik)'))
for (const id of ['#fGallery', '#fPhoto', '#fVideo']) $(id).addEventListener('change', e => {
  const f = e.target.files?.[0]; e.target.value = ''
  const r = G.get(openGid); if (f && r) sendFile(r, f)
})

document.addEventListener('visibilitychange', () => {
  if (!document.hidden && openGid) {
    const r = G.get(openGid); if (r) { r.unread = 0; updateTitle(); openChat(openGid) }
  }
})

// ═════════════════════════ start
let pendingAdd = null
let pendingJoin = null
function readHash() {
  const m = /^#add=(\d{1,10})(?:-([0-9A-Za-z]{8}))?$/.exec(location.hash)
  if (m) { pendingAdd = {num: m[1], kod: normKod(m[2] || '')}; history.replaceState(null, '', location.pathname + location.search) }
  const j = /^#join=([0-9a-z]{8,64})\.([A-Za-z0-9_-]{16,64})\.(.{0,200})$/.exec(location.hash)
  if (j) { let name = 'Grupa'; try { name = cleanNick(decodeURIComponent(j[3])) } catch {} pendingJoin = {gid: j[1], secret: j[2], name}; history.replaceState(null, '', location.pathname + location.search) }
}
async function doJoin(p) {
  if (!DB.groups[p.gid]) { DB.groups[p.gid] = {gid: p.gid, secret: p.secret, name: p.name.slice(0, 40), dm: null, seen: {}, created: Date.now(), ttl: 0}; save() }
  await startGroup(p.gid); openChat(p.gid); toast(`Dołączono do „${DB.groups[p.gid].name}” – poproś o kod rozmowy przez telefon`, 5000)
}
// Główna grupa – każdy, kto używa aplikacji, jest w niej automatycznie (jak grupa na Telegramie).
const MAIN_GID = 'bizzypizzymain01'
const MAIN_SECRET = 'JTbaD4KBscyT7L-aZuPZBZd9T7rdeQGv'
function ensureMain() {
  if (DB.groups[MAIN_GID] || DB.settings.leftMain) return
  DB.groups[MAIN_GID] = {gid: MAIN_GID, secret: MAIN_SECRET, name: 'Bizzy Pizzy 🍕', main: true, dm: null, seen: {}, created: 1, ttl: 0}; save()
}
async function boot() {
  show('#home'); renderHome()
  try { await openMyInbox() } catch (e) { toast('Błąd uruchamiania: ' + e.message, 8000) }
  ensureMain(); renderHome()
  for (const gid of Object.keys(DB.groups)) startGroup(gid).then(renderHomeSoon).catch(() => {})
  processOutbox(); setInterval(processOutbox, 30000)
  if (pendingAdd) { const p = pendingAdd; pendingAdd = null; if (p.num !== DB.me.number) { tab = 'contacts'; renderHome(); openAddContact(p.num, p.kod, true) } }
  if (pendingJoin) { const p = pendingJoin; pendingJoin = null; doJoin(p) }
}
window.addEventListener('hashchange', () => {
  readHash()
  if (pendingAdd && DB.me && myUid) { const p = pendingAdd; pendingAdd = null; openAddContact(p.num, p.kod, true) }
  if (pendingJoin && DB.me && myUid) { const p = pendingJoin; pendingJoin = null; doJoin(p) }
})
window.addEventListener('beforeunload', () => { inbox?.room.leave(); for (const r of G.values()) r.room.leave() })

if (!window.isSecureContext || !crypto.subtle) {
  document.body.innerHTML = '<div style="padding:30px;font:16px system-ui;color:#e7edf2">groupchat wymaga bezpiecznego połączenia (https). Otwórz aplikację z adresu https:// – instrukcja w README.</div>'
} else {
  readHash()
  try { navigator.storage?.persist?.() } catch {}
  if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => {})
  const start = () => DB.me ? boot() : showOnboarding()
  loadBuiltinIce().finally(() => lockInfo() ? showPinScreen(start) : start())
}
function showPinScreen(next) {
  show('#pin')
  const inp = $('#pinIn'), msg = $('#pinMsg'), go = $('#pinGo')
  const L = lockInfo()
  msg.textContent = L?.fails ? `Błędne próby: ${L.fails}` + (L.wipe ? ` (po 10 dane zostaną usunięte)` : '') : ''
  const tryIt = async () => {
    if (!inp.value) return
    go.disabled = true; msg.textContent = 'Sprawdzam…'
    const ok = await unlockPin(inp.value); inp.value = ''; go.disabled = false
    if (ok) { show(null); next() }
    else { const l = lockInfo(); msg.textContent = `❌ Zły PIN. Próby: ${l?.fails || 0}` + (l?.wipe ? ` z 10` : ''); inp.focus() }
  }
  go.onclick = tryIt; inp.onkeydown = e => { if (e.key === 'Enter') tryIt() }
  setTimeout(() => inp.focus(), 100)
}
// automatyczna blokada po 2 min w tle + rozmycie podglądu w przełączniku aplikacji
let hiddenAt = 0
document.addEventListener('visibilitychange', () => {
  if (document.hidden) hiddenAt = Date.now()
  else if (dbKey && hiddenAt && Date.now() - hiddenAt > 120000 && !call && !gcall) location.reload()
})
window.addEventListener('blur', () => { if (dbKey) document.body.classList.add('privacy') })
window.addEventListener('focus', () => document.body.classList.remove('privacy'))
// do testów
window.__gc = {get DB() { return DB }, G, get myUid() { return myUid }, get call() { return call }, get gcall() { return gcall }, visits}
