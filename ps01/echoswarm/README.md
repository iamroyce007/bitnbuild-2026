# EchoSwarm

**Every phone on site becomes an ear under the rubble.**
Bit N Build 2026, PSN001: Bio-Acoustic Swarm Sensing for Trapped Person Detection.

PSN001 asks for a swarm of custom acoustic sensors scattered across a collapse site. EchoSwarm uses the swarm that is already there: the phones in every rescuer's pocket. Rescuers install the app, drop their phones on the debris, and the command console turns their combined readings into one live map of where people are most likely trapped.

## What is in the box

| Part | Where | What it does |
|---|---|---|
| Sensor app (iOS + Android) | `mobile/` (Capacitor) using `public/node.html`, `public/js/node.js` | Listens with the mic and accelerometer and processes the sound on the phone. Sends only small detection summaries, never raw audio. |
| Command console | `public/command.html` | Live survivor-probability heat map, ranked candidates, swarm health, automation controls, rescue report. |
| Swarm server | `server/` (Node, Express, WebSocket) | Clock sync, sensor fusion, pattern detection, auto-mapping, knock-back probes, simulator. |

## Pipeline

```
 PHONE (edge)                                SERVER (fusion)                         COMMAND
 ─────────────────────────────────────────   ──────────────────────────────────────  ─────────────────────
 Mic ─▶ AudioWorklet (2.7 ms blocks)          Group detections from different         Heat map (probability)
        RMS · zero-cross · low/high band      phones within 160 ms = one sound        Candidates + confidence
        ─▶ adaptive noise floor               ─▶ grid search over the site:            Knock-back probe
        ─▶ onset detect ─▶ classify             · level vs distance (sound gets        Silence window
           impact / voice / other               quieter the further it travels)       Auto-map
 Accel ─▶ high-pass ─▶ vibration spike          · phones that heard nothing rule       Rescue report (PDF)
        ─▶ "came through the rubble" flag         out spots near them
 Clock ─▶ NTP-style sync over WebSocket         · arrival-time differences
        ─▶ onset time on the shared clock       · typical loudness of a knock
                                              ─▶ probability map, weighted by class,
                                                 vibration, silence window
                                              ─▶ accumulate with 150 s half-life
                                              ─▶ peaks ─▶ candidates
                                              ─▶ rhythm detector ─▶ "deliberate knocking"
```

### Automation that makes it new

1. **Acoustic self-mapping (Auto-map).** Inside a collapse there is no reliable GPS. Each phone plays a short 2–6.5 kHz chirp in its own time slot while every phone records. The distance between two phones comes from **two-way ranging (the BeepBeep method)**: `d = c/2 · ((tA←B − tA←A) − (tB←B − tB←A))`. Each phone only compares times measured on its own audio clock, so the phones' clocks don't need to agree. A technique called classical MDS then turns the full set of distances into a 2-D layout. Simulated accuracy is a few centimetres.
2. **Separating rubble from air.** A knock from someone trapped travels through the rubble, so a phone lying on the debris feels it as a small accelerometer spike at the same moment it hears it. Crew voices travel through the air and don't cause that spike. Detections with a matching vibration get 1.5× weight.
3. **Deliberate-signal detection.** Three or more knocks from the same spot within 10 s, evenly spaced (low variation in the gaps) or in groups, raise a "knock pattern" alert. Someone knocking on purpose is conscious and trying to be found.
4. **Silence window.** One button makes every phone vibrate, switch to high sensitivity, and analyse the quiet period for faint rhythmic sound repeating every 2–6 s (possible breathing). This automates the "everyone quiet!" call that rescue teams already make by hand.
5. **Knock-back consciousness probe.** Command picks a candidate. The phone nearest to it speaks "if you can hear me, knock three times" in **Tamil, Hindi or English**, plays three example knocks, then listens. A reply marks the candidate as RESPONDED and moves it to the top of the dig list.
6. **Negative evidence.** A phone that heard nothing is also information: the sound can't have come from anywhere close to it.
7. **Privacy by design.** Audio never leaves the phone. Only features are sent: onset time, level, class and confidence.

## Run it locally

```bash
npm install
npm start               # http://localhost:3000
npm test                # fusion + auto-map accuracy check
```

Open `http://localhost:3000/command`. You can demo without any phones using the Simulator panel:
1. **Scatter 6 phones**, then **Auto-map** (key `M`). The phones fly into place based on their chirps.
2. **Hide survivor**, then click the map. Optionally turn **Crew noise** on.
3. Watch the candidate appear on the heat map. Tick **Reveal hidden survivors** to show where the survivor really is.
4. **Silence window** (key `S`), then **Knock-back probe** on the candidate.
5. **Rescue report** gives a printable PDF with the map snapshot and dig priority.

Browsers only allow microphone access over HTTPS, so for real phones either deploy (below) or use a tunnel such as `npx localtunnel --port 3000` or `cloudflared tunnel --url http://localhost:3000`.

## Deploy the server

Any Node 18+ host with WebSocket support works.
- **Render:** push this folder and it picks up `render.yaml` (health check `/healthz`).
- **Docker:** `docker build -t echoswarm . && docker run -p 3000:3000 echoswarm`
- **Railway / Fly:** start command `node server/index.js`, port from `$PORT`.

## Build the apps

The app is the sensor node, packaged natively with Capacitor 6. It has native microphone, camera (QR join), motion and keep-awake permissions.

```bash
cd mobile
npm install
ECHOSWARM_SERVER=https://your-deployed-server npm run build:www   # bakes in the default server
npx cap sync
```

**Android** (JDK 17 + Android SDK):
```bash
cd mobile/android && ./gradlew assembleDebug
# APK: mobile/android/app/build/outputs/apk/debug/app-debug.apk
```

**iOS** (needs a Mac with Xcode 15+ and CocoaPods):
```bash
cd mobile && npx cap sync ios && npx cap open ios
# Pick your team under Signing & Capabilities, then Run on a device
```

On first launch: tap **Scan site QR code** on the command screen, then **Start listening**, and allow microphone and motion access. The QR code contains both the server address and the site code, so joining takes one scan.

## Known limits (honest notes for judges)
- Phone mics differ in sensitivity. The level model allows about 5.5 dB of spread, and the self-mapping chirp could later be used to calibrate each phone's gain.
- The browser clock sync is accurate to roughly 5–30 ms, so arrival timing is a weak signal. Localisation leans on loudness plus negative evidence, and then gets sharper as more knocks accumulate. The single-knock median error is about 1.2 m; after 6 knocks it's about 0.3 m (`npm test`, synthetic data).
- Phones must stay in the foreground with the screen on. The app keeps the screen awake automatically.
