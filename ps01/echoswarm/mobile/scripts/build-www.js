// Packs the shared sensor-node web code into the native app bundle (mobile/www).
// Set ECHOSWARM_SERVER to bake in a default server, e.g. ECHOSWARM_SERVER=https://echoswarm.onrender.com
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const pub = path.join(root, '..', 'public');
const www = path.join(root, 'www');
const server = process.env.ECHOSWARM_SERVER || '';

fs.rmSync(www, { recursive: true, force: true });
fs.mkdirSync(www, { recursive: true });
const copy = (from, to) => { fs.mkdirSync(path.dirname(to), { recursive: true }); fs.copyFileSync(from, to); };

for (const f of ['css/app.css', 'css/node.css', 'js/net.js', 'js/node.js', 'js/sensor-worklet.js', 'icons/icon.svg', 'icons/icon-192.png', 'icons/icon-512.png']) {
  copy(path.join(pub, f), path.join(www, f));
}
copy(require.resolve('jsqr/dist/jsQR.js', { paths: [path.join(root, '..')] }), path.join(www, 'vendor/jsqr.js'));

let html = fs.readFileSync(path.join(pub, 'node.html'), 'utf8');
html = html
  .replace(/<link rel="manifest"[^>]*>\s*/, '')
  .replace('<a class="wordmark" href="/">', '<a class="wordmark" href="#">')
  .replace('<title>EchoSwarm Node</title>', `<title>EchoSwarm</title>\n  <script>window.ES_DEFAULT_SERVER = ${JSON.stringify(server)};</script>`);
fs.writeFileSync(path.join(www, 'index.html'), html);
console.log(`www built${server ? ` (default server ${server})` : ''}`);
