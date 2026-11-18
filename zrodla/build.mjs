import * as esbuild from 'esbuild'
import fs from 'fs'
import crypto from 'crypto'
// zaszyfruj dane serwera TURN (AES-256-GCM); klucz rozbity: część w kodzie, część z SHA-256(APP|s)
let iceEnc = 'null'
if (fs.existsSync('src/turn.json')) {
  const plain = JSON.stringify(JSON.parse(fs.readFileSync('src/turn.json', 'utf8')))
  const key = crypto.randomBytes(32), iv = crypto.randomBytes(12), s = crypto.randomBytes(9).toString('base64url')
  const c = crypto.createCipheriv('aes-256-gcm', key, iv); const ct = Buffer.concat([c.update(plain, 'utf8'), c.final(), c.getAuthTag()])
  const salt = crypto.createHash('sha256').update('groupchat-p2p.v1|' + s).digest()
  const part = Buffer.from(key.map((x, i) => x ^ salt[i]))
  const b = x => Buffer.from(x).toString('base64url')
  iceEnc = JSON.stringify({k: b(part), i: b(iv), c: b(ct), s})
}
const r = await esbuild.build({define: {__ICE_ENC__: iceEnc},entryPoints: ['src/main.js'], bundle: true, format: 'esm', minify: true, write: false, target: 'es2022', legalComments: 'none'})
let js = r.outputFiles[0].text

if (/<\/script/i.test(js)) js = js.replace(/<\/script/gi, '<\\/script')
const html = fs.readFileSync('src/template.html', 'utf8').replace('/*__APP__*/', () => js)
fs.mkdirSync('dist', {recursive: true})
fs.writeFileSync('dist/index.html', html)
for (const f of ['manifest.webmanifest', 'icon.svg']) fs.copyFileSync('src/' + f, 'dist/' + f)
fs.writeFileSync('dist/sw.js', fs.readFileSync('src/sw.js', 'utf8').replace('__VER__', Date.now().toString(36)))
console.log('index.html', (html.length / 1024).toFixed(0) + ' KB')
