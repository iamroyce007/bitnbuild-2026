// EchoSwarm server: static PWA hosting + real-time WebSocket swarm hub.
const path = require('path');
const http = require('http');
const express = require('express');
const { WebSocketServer } = require('ws');
const { Site } = require('./site');

const PORT = process.env.PORT || 3000;
const app = express();
const sites = new Map();

const PUB = path.join(__dirname, '..', 'public');
app.use((req, res, next) => {
  // mic + motion sensors need these on some browsers
  res.setHeader('Permissions-Policy', 'microphone=(self), accelerometer=(self), gyroscope=(self), screen-wake-lock=(self)');
  next();
});
app.use(express.static(PUB, { extensions: ['html'] }));
app.get('/vendor/jsqr.js', (req, res) => res.sendFile(require.resolve('jsqr/dist/jsQR.js')));
app.get('/vendor/qrcode.js', (req, res) => res.sendFile(require.resolve('qrcode-generator/qrcode.js')));
app.get('/healthz', (req, res) => res.json({ ok: true, sites: sites.size, uptime: process.uptime() }));

const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function newCode() {
  let c;
  do c = Array.from({ length: 4 }, () => ALPHA[Math.floor(Math.random() * ALPHA.length)]).join('');
  while (sites.has(c));
  return c;
}
function getSite(code, create) {
  code = String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
  if (!code) return null;
  if (!sites.has(code) && create) sites.set(code, new Site(code));
  return sites.get(code) || null;
}

app.post('/api/sites', (req, res) => {
  const code = newCode();
  getSite(code, true);
  res.json({ code });
});
app.get('/api/sites/:code', (req, res) => {
  const s = getSite(req.params.code, false);
  if (!s) return res.status(404).json({ error: 'not found' });
  res.json({ code: s.code, nodes: s.nodes.size, candidates: s.candidates.length });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws) => {
  let site = null, node = null, role = null;
  ws.isAlive = true;
  ws.on('pong', () => (ws.isAlive = true));

  ws.on('message', (buf) => {
    let m;
    try { m = JSON.parse(buf); } catch { return; }

    // NTP-style clock sync: answered for any role, as fast as possible
    if (m.type === 'sync') return ws.send(JSON.stringify({ type: 'syncR', t0: m.t0, ts: Date.now() }));

    if (m.type === 'hello') {
      site = getSite(m.site, true);
      if (!site) return ws.close();
      role = m.role;
      if (role === 'command') {
        site.commands.add(ws);
        site.snapshotLog(ws);
        site.broadcastState();
      } else {
        node = site.attachNode(ws, m);
      }
      return;
    }
    if (!site) return;
    if (role === 'command') site.onCommandMessage(ws, m);
    else if (node) site.onNodeMessage(node, m);
  });

  ws.on('close', () => {
    if (!site) return;
    if (role === 'command') site.commands.delete(ws);
    else if (node && node.ws === ws) site.detachNode(node);
  });
});

// heartbeat + idle site cleanup
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false;
    ws.ping();
  }
  for (const [code, s] of sites) {
    const idle = !s.commands.size && ![...s.nodes.values()].some((n) => n.ws);
    if (idle) { s.idleSince = s.idleSince || Date.now(); if (Date.now() - s.idleSince > 6 * 3600e3) { s.destroy(); sites.delete(code); } }
    else s.idleSince = 0;
  }
}, 15000);

server.listen(PORT, () => {
  const nets = require('os').networkInterfaces();
  const lan = Object.values(nets).flat().filter((a) => a && a.family === 'IPv4' && !a.internal).map((a) => a.address);
  console.log(`\n  EchoSwarm running\n  ▸ Local:   http://localhost:${PORT}`);
  lan.forEach((ip) => console.log(`  ▸ LAN:     http://${ip}:${PORT}   (phones need HTTPS for the mic; see README)`));
  console.log('');
});
