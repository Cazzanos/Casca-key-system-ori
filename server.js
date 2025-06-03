const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const moment = require('moment-timezone');
const crypto = require("crypto");

function generateObfuscatedEndpoint(name) {
    return crypto.createHash("sha256").update(name + "secret-key").digest("hex").substring(0, 15);
}

const OBF_CHECKPOINT2 = generateObfuscatedEndpoint("checkpoint2");
const OBF_KEYGEN = generateObfuscatedEndpoint("key-generated");

const app = express();
app.set('trust proxy', true);
const PORT = 3000;
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));



app.use((req, res, next) => {
    if (req.path === '/blacklist' || req.path.startsWith('/admin')) return next();
    
    const ip = getClientIp(req);
    const blacklist = loadData(BLACKLIST_FILE);
    
    const isBlacklisted = blacklist.some(entry => 
        entry.type === 'ip' && 
        entry.value === ip && 
        (entry.expiry === 'permanent' || entry.expiry > Date.now())
    );
    
    if (isBlacklisted) return res.redirect('/blacklist');
    next();
});

const DATA_PATH = '/root/basement/';
const KEYS_FILE = path.join(DATA_PATH, 'keys.json');
const BLACKLIST_FILE = path.join(DATA_PATH, 'blacklist.json');
const PROGRESS_FILE = path.join(DATA_PATH, 'progress.json');
const NOTIFICATIONS_FILE = path.join(DATA_PATH, 'notifications.json');
const SCRIPT_FILE = path.join(DATA_PATH, 'basement.lua');

[KEYS_FILE, BLACKLIST_FILE, NOTIFICATIONS_FILE, PROGRESS_FILE].forEach(file => {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(file, JSON.stringify([]));
    }
});

const OBFUSCATED_ENDPOINTS = {
    checkpoint2: generateObfuscatedEndpoint("checkpoint2"),
    keyGenerated: generateObfuscatedEndpoint("keyGenerated")
};

function generateStepToken() {
    return crypto.randomBytes(32).toString('hex');
}

function verifyToken(ip, step, token) {
    const progress = loadData(PROGRESS_FILE);
    const userProgress = progress.find(entry => entry.ip === ip);
    
    console.log(`🔑 Verification for ${ip} at ${step}`);
    console.log(`Stored token: ${userProgress?.tokens?.[step]}`);
    console.log(`Received token: ${token}`);

    return userProgress?.tokens?.[step] === token;
}

app.get("/linkvertise-redirect", (req, res) => {
    const ip = getClientIp(req);
    const { step } = req.query;

    const validSteps = {
        "checkpoint2": OBFUSCATED_ENDPOINTS.checkpoint2,
        "key-generated": OBFUSCATED_ENDPOINTS.keyGenerated
    };

    if (!validSteps[step]) {
        console.log(`🚨 ERROR: Invalid step "${step}" requested by IP ${ip}`);
        return res.redirect("/");
    }

    console.log(`✅ Redirecting ${ip} to hashed endpoint: /${validSteps[step]}`);
    res.redirect(`/${validSteps[step]}`);
});

function saveProgress(ip, checkpointName) {
    const progressData = loadData(PROGRESS_FILE);
    let userProgress = progressData.find(entry => entry.ip === ip);

    if (!userProgress) {
        userProgress = { 
            ip: ip, 
            checkpoints: [],
            lastAccess: Date.now()
        };
        progressData.push(userProgress);
    }

    if (!userProgress.checkpoints.includes(checkpointName)) {
        userProgress.checkpoints.push(checkpointName);
        console.log(`✅ Progress saved for IP ${ip}: Completed ${checkpointName}`);
    }
    
    userProgress.lastAccess = Date.now();
    
    saveData(PROGRESS_FILE, progressData);
}

function cleanOldProgress() {
  const progress = loadData(PROGRESS_FILE);
  const HOUR = 3600000;
  
  const cleaned = progress.filter(entry => {
    // Keep entries with active keys
    const hasActiveKey = loadData(KEYS_FILE).some(
      key => key.ip === entry.ip && !key.expired
    );
    
    // Keep entries from last 72h if no key
    return hasActiveKey || (Date.now() - entry.lastAccess < 72 * HOUR);
  });

  saveData(PROGRESS_FILE, cleaned);
}

// Run every hour
setInterval(cleanOldProgress, 3600000);

// Funcții pentru gestionarea datelor
function loadData(file) {
    const data = fs.readFileSync(file);
    return JSON.parse(data);
}

function saveData(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// Funcție pentru generarea unei chei unice
function generateKey() {
    return 'TheBasement_' + uuidv4().slice(0, 10);  // Prefix followed by 10 characters
}

// Funcție pentru verificarea și adăugarea unei chei
function createKey(ip, maxUsers = 2) {
    const keys = loadData(KEYS_FILE);
    const existingKey = keys.find(key => key.ip === ip && !key.expired);

    if (existingKey) {
        if (Date.now() > existingKey.expiresAt) {
            // Cheia existentă este expirată, creăm una nouă
            existingKey.expired = true;
            saveData(KEYS_FILE, keys);
        } else {
            return existingKey;  // Cheia este încă validă
        }
    }

    const newKey = {
        key: generateKey(),
        ip: ip,
        maxUsers: maxUsers,
        createdAt: Date.now(),
        expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 ore
        expired: false,
        inUse: false,
        usedBy: []
    };

    keys.push(newKey);
    saveData(KEYS_FILE, keys);

    return newKey;
}

// Funcție pentru crearea unei chei personalizate
function createCustomKey(key, duration, maxUsers = 1) {
    const keys = loadData(KEYS_FILE);
    const now = Date.now();
    const expiresAt = now + parseInt(duration) * 60 * 60 * 1000; // Durata în ore

    const newKey = {
        key: key,
        ip: 'admin',
        maxUsers: maxUsers,
        createdAt: now,
        expiresAt: expiresAt,
        expired: false,
        inUse: false,
        usedBy: []
    };

    keys.push(newKey);
    saveData(KEYS_FILE, keys);

    return newKey;
}

// Funcție pentru verificarea blacklist-ului
function isBlacklisted(ip, playerName) {
    const blacklist = loadData(BLACKLIST_FILE);
    const now = Date.now();

    // Verifică dacă IP-ul este pe blacklist
    const blacklistedIP = blacklist.find(entry => entry.type === 'ip' && entry.value === ip && (entry.expiry === 'permanent' || entry.expiry > now));
    if (blacklistedIP) {
        return { blacklisted: true, message: `Your IP has been blacklisted${blacklistedIP.expiry !== 'permanent' ? ` until ${moment(blacklistedIP.expiry).format('LLLL')}` : ''}` };
    }

    // Verifică dacă numele jucătorului este pe blacklist
    const blacklistedPlayer = blacklist.find(entry => entry.type === 'player' && entry.value.toLowerCase() === playerName.toLowerCase() && (entry.expiry === 'permanent' || entry.expiry > now));
    if (blacklistedPlayer) {
        return { blacklisted: true, message: `You have been blacklisted${blacklistedPlayer.expiry !== 'permanent' ? ` until ${moment(blacklistedPlayer.expiry).format('LLLL')}` : ''}` };
    }

    return { blacklisted: false };
}

// Middleware pentru verificarea codului de acces
function adminsg(req, res, next) {
    const { access_code } = req.query;
    if ((req.path === '/keys' && access_code === 'vasiocburatiocsukos') ||
        (req.path === '/admin' && access_code === 'buratiocadminboscotos')) {
        return next();
    }
    res.status(401).send('Unauthorized');
}

function checkAccess(req, res, next) {
    const ip = getClientIp(req);
    const path = req.path;
    const progress = loadData(PROGRESS_FILE);
    const userProgress = progress.find(entry => entry.ip === ip);

    console.log(`🛂 Access check for ${ip} at ${path}`);
    console.log(`User progress: ${JSON.stringify(userProgress)}`);

    // Allow access if they have a valid token for this step
    const token = req.query.token;
    if (token && verifyToken(ip, path.slice(1), token)) {
        console.log(`✅ Token access granted for ${path}`);
        return next();
    }

    // Existing checkpoint verification
    const requiredSteps = {
        [`/${OBF_CHECKPOINT2}`]: ['redirect-to-linkvertise'],
        [`/${OBF_KEYGEN}`]: ['redirect-to-linkvertise', 'checkpoint2']
    }[path] || [];

    if (requiredSteps.every(step => userProgress?.checkpoints.includes(step))) {
        return next();
    }

    console.log(`🚫 Access denied for ${ip} at ${path}`);
    blacklistIp(ip, "Bypass attempt");
    res.redirect("/blacklist");
}

function generateBlacklistId() {
    return Math.random().toString(36).substring(2, 8).toUpperCase();
}

function blacklistIp(ip, reason) {
    let blacklist = loadData(BLACKLIST_FILE);
    const existingEntry = blacklist.find(entry => entry.type === "ip" && entry.value === ip);
    const expiryTime = Date.now() + 1000; // 1 second in milliseconds

    if (existingEntry) {
        existingEntry.reason = reason || existingEntry.reason;
        existingEntry.expiry = expiryTime;
        if (!existingEntry.blacklistId) {
            existingEntry.blacklistId = Math.random().toString(36).substring(2, 8).toUpperCase();
        }
    } else {
        blacklist.push({
            type: "ip",
            value: ip,
            reason: reason || "Bypassed security",
            expiry: expiryTime,
            blacklistId: Math.random().toString(36).substring(2, 8).toUpperCase()
        });
    }

    saveData(BLACKLIST_FILE, blacklist);
}

function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    let ip = forwarded ? forwarded.split(',')[0] : req.socket.remoteAddress;

    if (ip && ip.startsWith('::ffff:')) ip = ip.substring(7);

    return ip ? ip.trim() : 'unknown';
}

function removeExpiredKeys() {
    let keys = loadData(KEYS_FILE);
    const now = Date.now();

    keys = keys.filter(key => {
        if (key.expiresAt !== "permanent" && key.expiresAt <= now) {
            console.log(`🟡 Key expired for ${key.ip}, resetting progress.`);
            resetProgress(key.ip); // ✅ Reset progress when key expires
            return false;
        }
        return true;
    });

    saveData(KEYS_FILE, keys);
}

function removeAllKeys() {
    saveData(KEYS_FILE, []);
}

function resetProgress(ip) {
    const progress = loadData(PROGRESS_FILE);
    let updatedProgress = progress.map(entry => {
        if (entry.ip === ip) {
            entry.checkpoints = []; // Reset checkpoints instead of removing progress
        }
        return entry;
    });
    saveData(PROGRESS_FILE, updatedProgress);
}

// Route pentru pagina principală
app.get('/', (req, res) => {
    const ip = getClientIp(req); 
    const blacklist = loadData(BLACKLIST_FILE); 
    const blacklisted = blacklist.find(entry => entry.type === 'ip' && entry.value === ip && entry.expiry === 'permanent');

    if (blacklisted) {
        return res.redirect('/blacklist');
    }

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
            <title>BSMT Hub Key System</title>
            <link href="https://fonts.googleapis.com/css2?family=Orbitron :wght@500&display=swap" rel="stylesheet">
            <style>
                :root {
                    --primary: #00ffd5;
                    --secondary: #1e1e2f;
                    --hover-bg: #3e3e5e;
                    --glass-bg: rgba(255, 255, 255, 0.05);
                    --shadow: rgba(255, 255, 255, 0.1);
                }

                body {
                    margin: 0;
                    font-family: 'Orbitron', sans-serif;
                    background: linear-gradient(135deg, #0a0a0f, #1c1c24);
                    color: white;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    overflow: hidden;
                }

                .container {
                    background: var(--glass-bg);
                    backdrop-filter: blur(20px);
                    border-radius: 20px;
                    padding: 40px 30px;
                    text-align: center;
                    box-shadow: 0 0 30px var(--shadow);
                    animation: fadeInUp 1s ease-out;
                    z-index: 2;
                    position: relative;
                }

                h1 {
                    font-size: 2rem;
                    margin-bottom: 30px;
                    color: var(--primary);
                    text-shadow: 0 0 10px rgba(0, 255, 213, 0.4);
                }

                .buttons {
                    display: flex;
                    flex-direction: column;
                    gap: 15px;
                    margin-top: 20px;
                }

                a.button-link {
                    display: inline-block;
                    background: var(--secondary);
                    color: white;
                    padding: 14px 25px;
                    border-radius: 10px;
                    text-decoration: none;
                    font-size: 16px;
                    transition: all 0.3s ease;
                    position: relative;
                    overflow: hidden;
                }

                a.button-link::before {
                    content: '';
                    position: absolute;
                    top: 50%;
                    left: -100%;
                    width: 300%;
                    height: 300%;
                    background: radial-gradient(circle at center, rgba(0, 255, 213, 0.2), transparent 70%);
                    transform: translateY(-50%);
                    transition: all 0.5s ease;
                    pointer-events: none;
                }

                a.button-link:hover::before {
                    left: 100%;
                }

                a.button-link:hover {
                    background: var(--hover-bg);
                    transform: scale(1.05);
                }

                .discord-icon {
                    position: fixed;
                    bottom: 20px;
                    right: 20px;
                    width: 60px;
                    height: 60px;
                    cursor: pointer;
                    filter: drop-shadow(0 0 10px rgba(0, 255, 213, 0.5));
                    transition: transform 0.3s ease;
                    z-index: 10;
                    border-radius: 20%;
                }

                .discord-icon:hover {
                    transform: scale(1.1) rotate(10deg);
                }

                /* Particle Background */
                canvas#bg {
                    position: fixed;
                    top: 0;
                    left: 0;
                    z-index: 1;
                }

                @keyframes fadeInUp {
                    from { opacity: 0; transform: translateY(30px); }
                    to { opacity: 1; transform: translateY(0); }
                }

                @media (max-width: 600px) {
                    h1 {
                        font-size: 1.5rem;
                    }
                    .container {
                        padding: 30px 20px;
                    }
                }
            </style>
        </head>
        <body>

            <!-- Canvas Background -->
            <canvas id="bg"></canvas>

            <!-- Main Content -->
            <div class="container">
                <h1>Welcome to BSMT Hub Key System</h1>
                <div class="buttons">
                    <a href="/redirect-to-linkvertise?step=checkpoint2" class="button-link">Generate a Key</a>
                    <a href="/key-info" class="button-link">Key Info</a>
                    <a href="/script-info" class="button-link">Script Info</a>
                    <a href="/buy" class="button-link">Buy Key</a>
                </div>
            </div>

            <!-- Discord Icon -->
            <img src="https://cdn.discordapp.com/embed/avatars/0.png " class="discord-icon" onclick="window.location.href='https://discord.gg/We4FtdFD2D '" alt="Discord">

            <!-- Particle JS Script -->
            <script>
                const canvas = document.getElementById('bg');
                const ctx = canvas.getContext('2d');
                let width, height;
                let particles = [];

                function resize() {
                    width = window.innerWidth;
                    height = window.innerHeight;
                    canvas.width = width;
                    canvas.height = height;
                }

                class Particle {
                    constructor() {
                        this.x = Math.random() * width;
                        this.y = Math.random() * height;
                        this.vx = (Math.random() - 0.5) * 0.5;
                        this.vy = (Math.random() - 0.5) * 0.5;
                        this.radius = Math.random() * 2 + 1;
                        this.alpha = Math.random() * 0.5 + 0.2;
                    }

                    draw() {
                        ctx.beginPath();
                        ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
                        ctx.fillStyle = 'rgba(0, 255, 213, ' + this.alpha + ')';
                        ctx.fill();
                    }

                    update() {
                        this.x += this.vx;
                        this.y += this.vy;

                        if (this.x > width || this.x < 0) this.vx *= -1;
                        if (this.y > height || this.y < 0) this.vy *= -1;

                        this.draw();
                    }
                }

                function initParticles() {
                    particles = [];
                    const count = Math.floor(width / 10);
                    for (let i = 0; i < count; i++) {
                        particles.push(new Particle());
                    }
                }

                function animate() {
                    ctx.clearRect(0, 0, width, height);
                    particles.forEach(p => p.update());
                    requestAnimationFrame(animate);
                }

                window.addEventListener('resize', () => {
                    resize();
                    initParticles();
                });

                resize();
                initParticles();
                animate();
            </script>
        </body>
        </html>
    `);
});

app.get('/buy', (req, res) => {
  res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
      <title>Buy Key | BSMT Hub</title>
      <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500&display=swap" rel="stylesheet">
      <style>
          :root {
              --primary: #00ffd5;
              --secondary: #1e1e2f;
              --hover-bg: #3e3e5e;
              --glass-bg: rgba(255, 255, 255, 0.05);
              --shadow: rgba(255, 255, 255, 0.1);
          }

          body {
              margin: 0;
              font-family: 'Orbitron', sans-serif;
              background: linear-gradient(135deg, #0a0a0f, #1c1c24);
              color: white;
              display: flex;
              justify-content: center;
              align-items: center;
              height: 100vh;
              overflow: hidden;
          }

          .container {
              background: var(--glass-bg);
              backdrop-filter: blur(20px);
              border-radius: 20px;
              padding: 40px 30px;
              text-align: center;
              box-shadow: 0 0 30px var(--shadow);
              animation: fadeInUp 1s ease-out;
              z-index: 2;
              position: relative;
          }

          h1 {
              font-size: 2rem;
              margin-bottom: 30px;
              color: var(--primary);
              text-shadow: 0 0 10px rgba(0, 255, 213, 0.4);
          }

          .paypal-button-wrapper {
              display: grid;
              gap: 25px;
              grid-template-columns: 1fr;
              margin-top: 30px;
          }

          .product-box {
              text-align: center;
          }

          .label {
              margin-bottom: 10px;
              font-size: 1rem;
              font-weight: bold;
              color: var(--primary);
              text-shadow: 0 0 6px rgba(0, 255, 213, 0.3);
          }

          .discord-icon {
              position: fixed;
              bottom: 20px;
              right: 20px;
              width: 60px;
              height: 60px;
              cursor: pointer;
              filter: drop-shadow(0 0 10px rgba(0, 255, 213, 0.5));
              transition: transform 0.3s ease;
              z-index: 10;
              border-radius: 20%;
          }

          .discord-icon:hover {
              transform: scale(1.1) rotate(10deg);
          }

          canvas#bg {
              position: fixed;
              top: 0;
              left: 0;
              z-index: 1;
          }

          @keyframes fadeInUp {
              from { opacity: 0; transform: translateY(30px); }
              to { opacity: 1; transform: translateY(0); }
          }
      </style>
  </head>
  <body>
      <canvas id="bg"></canvas>
      <div class="container">
          <h1>Buy a Key</h1>
          <div class="paypal-button-wrapper">
              <div class="product-box">
                  <div class="label">🟢 1 Week - $0.50</div>
                  <div id="paypal-1week"></div>
              </div>
              <div class="product-box">
                  <div class="label">🟡 1 Month - $1.00</div>
                  <div id="paypal-1month"></div>
              </div>
              <div class="product-box">
                  <div class="label">🔵 1 Year - $5.00</div>
                  <div id="paypal-1year"></div>
              </div>
              <div class="product-box">
                  <div class="label">🔴 Permanent - $8.00</div>
                  <div id="paypal-permanent"></div>
              </div>
          </div>
      </div>

      <img src="https://cdn.discordapp.com/embed/avatars/0.png" class="discord-icon" onclick="window.location.href='https://discord.gg/We4FtdFD2D'" alt="Discord">

      <script src="https://www.paypal.com/sdk/js?client-id=AfcZrdx_OZvZIIaB-XrLjoxnEOhGdQTe4JV2qouu707UrGbpo7u-Hc2c6OBgB6NT_MYK1E83jHbFMY0Q&currency=USD"></script>
        const durations = {
          '1week': { value: '0.50', label: '1 Week', hours: 168 },
          '1month': { value: '1.00', label: '1 Month', hours: 720 },
          '1year': { value: '5.00', label: '1 Year', hours: 8760 },
          'permanent': { value: '8.00', label: 'Permanent', hours: 'permanent' }
        };

        for (const id in durations) {
          paypal.Buttons({
            style: { layout: 'horizontal', color: 'gold', shape: 'pill', label: 'paypal' },
            createOrder: function(data, actions) {
              return actions.order.create({
                purchase_units: [{
                  amount: { value: durations[id].value }
                }]
              });
            },
            onApprove: function(data, actions) {
              return actions.order.capture().then(function(details) {
                fetch('/api/paypal-success', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ 
                    payer: details.payer,
                    hours: durations[id].hours 
                  })
                })
                .then(res => res.json())
                .then(data => {
                  window.location.href = '/key?value=' + encodeURIComponent(data.key);
                });
              });
            }
          }).render('#paypal-' + id);
        }
      </script>

      <script>
          const canvas = document.getElementById('bg');
          const ctx = canvas.getContext('2d');
          let width, height, particles = [];

          function resize() {
              width = window.innerWidth;
              height = window.innerHeight;
              canvas.width = width;
              canvas.height = height;
          }

          class Particle {
              constructor() {
                  this.x = Math.random() * width;
                  this.y = Math.random() * height;
                  this.vx = (Math.random() - 0.5) * 0.5;
                  this.vy = (Math.random() - 0.5) * 0.5;
                  this.radius = Math.random() * 2 + 1;
                  this.alpha = Math.random() * 0.5 + 0.2;
              }

              draw() {
                  ctx.beginPath();
                  ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
                  ctx.fillStyle = 'rgba(0, 255, 213, ' + this.alpha + ')';
                  ctx.fill();
              }

              update() {
                  this.x += this.vx;
                  this.y += this.vy;
                  if (this.x > width || this.x < 0) this.vx *= -1;
                  if (this.y > height || this.y < 0) this.vy *= -1;
                  this.draw();
              }
          }

          function initParticles() {
              particles = [];
              const count = Math.floor(width / 10);
              for (let i = 0; i < count; i++) {
                  particles.push(new Particle());
              }
          }

          function animate() {
              ctx.clearRect(0, 0, width, height);
              particles.forEach(p => p.update());
              requestAnimationFrame(animate);
          }

          window.addEventListener('resize', () => {
              resize();
              initParticles();
          });

          resize();
          initParticles();
          animate();
      </script>
  </body>
  </html>
  `);
});

app.post('/api/paypal-success', express.json(), async (req, res) => {
  const ip = getClientIp(req);
  const { hours, payer } = req.body;

  let newKey;
  let durationLabel = hours === 'permanent' ? 'Permanent' : `${hours}h`;
  let price = {
    168: '$0.50',
    720: '$1.00',
    8760: '$5.00',
    permanent: '$8.00'
  }[hours] || 'N/A';

  if (hours === 'permanent') {
    newKey = {
      key: generateKey(),
      ip,
      maxUsers: 2,
      createdAt: Date.now(),
      expiresAt: 'permanent',
      expired: false,
      inUse: false,
      usedBy: []
    };
  } else {
    newKey = {
      key: generateKey(),
      ip,
      maxUsers: 2,
      createdAt: Date.now(),
      expiresAt: Date.now() + parseInt(hours) * 60 * 60 * 1000,
      expired: false,
      inUse: false,
      usedBy: []
    };
  }

  const keys = loadData(KEYS_FILE);
  keys.push(newKey);
  saveData(KEYS_FILE, keys);

  const webhookUrl = "https://discord.com/api/webhooks/1379371044724539405/zfvRR_WKfSq9mDYNjey0GJfkuHBHyQftoxRsNX7j__b-1cez2hrVPQIaNHpJ3YJ7EoBl";

  const message = {
    content: `🎉 **New Key Purchased!**`,
    embeds: [
      {
        color: 0x00ffd5,
        title: "Key Purchase Info",
        fields: [
          { name: "🧪 Key", value: `\`${newKey.key}\``, inline: false },
          { name: "📦 Duration", value: `${durationLabel}`, inline: true },
          { name: "💸 Price", value: `${price}`, inline: true },
          { name: "🌐 IP", value: ip, inline: false }
        ],
        timestamp: new Date().toISOString()
      }
    ]
  };

  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(message)
    });
  } catch (err) {
    console.error("Failed to send webhook:", err.message);
  }

  res.json({ key: newKey.key });
});

app.get('/key', (req, res) => {
  const key = req.query.value;

  if (!key) return res.redirect('/buy');

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Your BSMT Key</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500&display=swap" rel="stylesheet">
        <style>
            :root {
                --primary: #00ffd5;
                --secondary: #1e1e2f;
                --glass-bg: rgba(255, 255, 255, 0.05);
                --shadow: rgba(255, 255, 255, 0.1);
            }
            body {
                margin: 0;
                font-family: 'Orbitron', sans-serif;
                background: linear-gradient(135deg, #0a0a0f, #1c1c24);
                color: white;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                overflow: hidden;
            }
            .container {
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                border-radius: 20px;
                padding: 40px 30px;
                text-align: center;
                box-shadow: 0 0 30px var(--shadow);
                animation: fadeInUp 1s ease-out;
                z-index: 2;
                position: relative;
            }
            h1 {
                font-size: 2rem;
                margin-bottom: 20px;
                color: var(--primary);
            }
            .key-box {
                font-size: 1.5rem;
                color: #fff;
                padding: 20px;
                border-radius: 10px;
                background: rgba(255, 255, 255, 0.1);
                box-shadow: 0 0 20px var(--shadow);
                word-break: break-word;
            }
            canvas#bg {
                position: fixed;
                top: 0;
                left: 0;
                z-index: 1;
            }
            @keyframes fadeInUp {
                from { opacity: 0; transform: translateY(30px); }
                to { opacity: 1; transform: translateY(0); }
            }
        </style>
    </head>
    <body>
        <canvas id="bg"></canvas>
        <div class="container">
            <h1>Your Key</h1>
            <div class="key-box">${key}</div>
        </div>

        <script>
            const canvas = document.getElementById('bg');
            const ctx = canvas.getContext('2d');
            let width, height, particles = [];

            function resize() {
                width = window.innerWidth;
                height = window.innerHeight;
                canvas.width = width;
                canvas.height = height;
            }

            class Particle {
                constructor() {
                    this.x = Math.random() * width;
                    this.y = Math.random() * height;
                    this.vx = (Math.random() - 0.5) * 0.5;
                    this.vy = (Math.random() - 0.5) * 0.5;
                    this.radius = Math.random() * 2 + 1;
                    this.alpha = Math.random() * 0.5 + 0.2;
                }

                draw() {
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
                    ctx.fillStyle = 'rgba(0, 255, 213, ' + this.alpha + ')';
                    ctx.fill();
                }

                update() {
                    this.x += this.vx;
                    this.y += this.vy;
                    if (this.x > width || this.x < 0) this.vx *= -1;
                    if (this.y > height || this.y < 0) this.vy *= -1;
                    this.draw();
                }
            }

            function initParticles() {
                particles = [];
                const count = Math.floor(width / 10);
                for (let i = 0; i < count; i++) {
                    particles.push(new Particle());
                }
            }

            function animate() {
                ctx.clearRect(0, 0, width, height);
                particles.forEach(p => p.update());
                requestAnimationFrame(animate);
            }

            window.addEventListener('resize', () => {
                resize();
                initParticles();
            });

            resize();
            initParticles();
            animate();
        </script>
    </body>
    </html>
  `);
});

app.get('/key-info', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
      <title>Key Info | BSMT Hub</title>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@500;600&display=swap" rel="stylesheet">
      <style>
        :root {
          --primary: #00ffd5;
          --secondary: #1e1e2f;
          --hover-bg: #3e3e5e;
          --glass-bg: rgba(255, 255, 255, 0.05);
          --shadow: rgba(255, 255, 255, 0.1);
        }

        * {
          box-sizing: border-box;
        }

        body {
          margin: 0;
          font-family: 'Inter', sans-serif;
          background: linear-gradient(135deg, #0a0a0f, #1c1c24);
          color: white;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          padding: 30px 16px;
          overflow: hidden;
        }

        .container {
          background: var(--glass-bg);
          backdrop-filter: blur(20px);
          border-radius: 20px;
          padding: 40px 32px;
          box-shadow: 0 0 30px var(--shadow);
          text-align: center;
          animation: fadeInUp 0.8s ease;
          max-width: 500px;
          width: 100%;
          z-index: 2;
        }

        h1 {
          font-size: 1.9rem;
          font-weight: 600;
          margin-bottom: 24px;
          color: var(--primary);
        }

        input[type="text"] {
          width: 100%;
          padding: 14px 20px;
          font-size: 0.95rem;
          border-radius: 10px;
          border: none;
          background: #12121a;
          color: var(--primary);
          box-shadow: inset 0 0 10px rgba(0,255,213,0.1);
          margin-bottom: 20px;
          outline: none;
          transition: 0.3s ease;
        }

        input[type="text"]:focus {
          box-shadow: 0 0 12px rgba(0,255,213,0.4);
        }

        .button-group {
          display: flex;
          flex-direction: column;
          gap: 16px;
        }

        .top-buttons {
          display: flex;
          flex-wrap: wrap;
          gap: 12px;
          justify-content: center;
        }

        button {
          background: var(--secondary);
          color: white;
          padding: 12px 22px;
          font-size: 0.95rem;
          border: none;
          border-radius: 10px;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        button:hover {
          background: var(--hover-bg);
          transform: scale(1.05);
        }

        .go-back {
          margin-top: 20px;
          display: inline-block;
          padding: 12px 20px;
          background: var(--secondary);
          border-radius: 10px;
          text-decoration: none;
          color: white;
          font-weight: 500;
          transition: 0.3s ease;
        }

        .go-back:hover {
          background: var(--hover-bg);
          transform: scale(1.05);
        }

        .message {
          margin-top: 15px;
          font-size: 0.9rem;
          font-weight: 500;
          transition: opacity 0.3s ease;
        }

        .error {
          color: #ff6b6b;
        }

        .success {
          color: #2ecc71;
        }

        .discord-icon {
          position: fixed;
          bottom: 20px;
          right: 20px;
          width: 60px;
          height: 60px;
          cursor: pointer;
          z-index: 10;
          filter: drop-shadow(0 0 10px rgba(0,255,213,0.5));
          transition: transform 0.3s ease;
          border-radius: 20%;
        }

        .discord-icon:hover {
          transform: scale(1.1) rotate(10deg);
        }

        @keyframes fadeInUp {
          from { opacity: 0; transform: translateY(30px); }
          to { opacity: 1; transform: translateY(0); }
        }

        @media (max-width: 600px) {
          h1 {
            font-size: 1.5rem;
          }

          button {
            width: 100%;
          }

          .top-buttons {
            flex-direction: column;
            gap: 10px;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Key Authentication</h1>
        <input type="text" id="keyInput" placeholder="Paste your key..." />
        <div class="button-group">
          <div class="top-buttons">
            <button onclick="searchKey()">Search Key</button>
            <button onclick="findMyKey()">Find My Key IP</button>
          </div>
          <a href="/" class="go-back">⬅ Return Home</a>
        </div>
        <p id="message" class="message"></p>
      </div>

      <img src="https://cdn.discordapp.com/embed/avatars/0.png" class="discord-icon" onclick="window.location.href='https://discord.gg/WPR9sJfZaJ'" alt="Discord">

      <script>
        function searchKey() {
          const key = document.getElementById("keyInput").value.trim();
          const messageBox = document.getElementById("message");

          if (!key) {
            messageBox.innerText = "Please enter a key!";
            messageBox.className = "message error";
            return;
          }

          fetch('/search-key?key=' + encodeURIComponent(key))
            .then(res => res.json())
            .then(data => {
              if (data.success) {
                messageBox.className = "message success";
                window.location.href = '/key-details?key=' + encodeURIComponent(key);
              } else {
                messageBox.innerText = data.message || "Invalid or expired key.";
                messageBox.className = "message error";
              }
            })
            .catch(() => {
              messageBox.innerText = "An error occurred while searching.";
              messageBox.className = "message error";
            });
        }

        function findMyKey() {
          const messageBox = document.getElementById("message");

          fetch('/find-my-key')
            .then(res => res.json())
            .then(data => {
              if (data.success) {
                messageBox.className = "message success";
                window.location.href = '/key-details?key=' + encodeURIComponent(data.key);
              } else {
                messageBox.innerText = data.message || "No active key found.";
                messageBox.className = "message error";
              }
            })
            .catch(() => {
              messageBox.innerText = "An error occurred while finding your key.";
              messageBox.className = "message error";
            });
        }
      </script>
    </body>
    </html>
  `);
});

app.get('/search-key', (req, res) => {
    const { key } = req.query;
    const keys = loadData(KEYS_FILE);
    const foundKey = keys.find(entry =>
        entry.key === key &&
        !entry.expired &&
        (entry.expiresAt === 'permanent' || entry.expiresAt > Date.now())
    );

    if (!foundKey) {
        return res.json({
            success: false,
            message: 'Invalid or expired key'
        });
    }

    res.json({ success: true });
});

app.get('/find-my-key', (req, res) => {
    const ip = getClientIp(req);
    const keys = loadData(KEYS_FILE);
    const userKey = keys.find(entry => 
        entry.ip === ip && 
        !entry.expired &&
        (entry.expiresAt === 'permanent' || entry.expiresAt > Date.now())
    );

    if (!userKey) {
        return res.json({ 
            success: false, 
            message: 'No active key found for your IP' 
        });
    }

    res.json({ success: true, key: userKey.key });
});

app.get("/updates", async (req, res) => {
    const GITHUB_UPDATES_URL = 'https://raw.githubusercontent.com/Cazzanos/Updates/main/BSMT';

    try {
        const response = await fetch(GITHUB_UPDATES_URL);
        const updates = await response.json();

        const renderDetails = (details) => {
            return details.map(line => {
                if (line.startsWith("•")) {
                    return `<li class="detail main"><span>✦</span>${line.slice(1).trim()}</li>`;
                } else if (line.startsWith("-")) {
                    return `<li class="detail sub"><span>↳</span>${line.slice(1).trim()}</li>`;
                } else {
                    return `<li class="detail">${line}</li>`;
                }
            }).join("");
        };

        const htmlCards = updates.map(update => `
            <div class="update-card animate">
                <div class="header">
                    <h2>${update.game}</h2>
                    <span>${new Date(update.date).toLocaleDateString()}</span>
                </div>
                <ul>${renderDetails(update.details)}</ul>
                <div class="version">${update.version}</div>
            </div>
        `).join("");

        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                <title>Updates | BSMT</title>
                <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
                <style>
                    body {
                        font-family: 'JetBrains Mono', monospace;
                        margin: 0;
                        padding: 40px 20px;
                        background: #0f1115;
                        color: #eee;
                        animation: fadeIn 0.8s ease-in;
                    }
                    h1 {
                        color: #00ffee;
                        text-align: center;
                        margin-bottom: 20px;
                        text-shadow: 0 0 10px #00ffee;
                    }
                    .updates-wrapper {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                        gap: 25px;
                        max-width: 1200px;
                        margin: auto;
                    }
                    .update-card {
                        background: rgba(255,255,255,0.04);
                        border: 1px solid rgba(255,255,255,0.08);
                        border-radius: 15px;
                        padding: 20px;
                        box-shadow: 0 0 10px rgba(0,255,255,0.15);
                        position: relative;
                        transition: transform 0.3s ease;
                    }
                    .update-card:hover {
                        transform: translateY(-5px);
                        box-shadow: 0 0 20px rgba(0,255,255,0.25);
                    }
                    .update-card .header {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 10px;
                    }
                    .update-card .header h2 {
                        margin: 0;
                        color: #00ffee;
                        font-size: 1.3rem;
                    }
                    .update-card ul {
                        list-style: none;
                        padding-left: 0;
                        margin-top: 10px;
                    }
                    .update-card .detail {
                        margin: 5px 0;
                        line-height: 1.4;
                    }
                    .update-card .detail span {
                        margin-right: 8px;
                        color: #ff00aa;
                    }
                    .update-card .detail.main {
                        font-weight: bold;
                        color: #00ffaa;
                    }
                    .update-card .detail.sub {
                        margin-left: 15px;
                        font-size: 0.9rem;
                        color: #ccc;
                    }
                    .version {
                        position: absolute;
                        top: 10px;
                        right: 10px;
                        font-size: 0.8rem;
                        background: #1b1e24;
                        border-radius: 5px;
                        padding: 3px 8px;
                        color: #0ff;
                        border: 1px solid #0ff;
                    }
                    @keyframes fadeIn {
                        from { opacity: 0; transform: translateY(10px); }
                        to { opacity: 1; transform: translateY(0); }
                    }
                </style>
            </head>
            <body>
                <h1>BSMT Script Updates</h1>
                <div class="updates-wrapper">${htmlCards}</div>
            </body>
            </html>
        `);
    } catch (err) {
        console.error("Update fetch failed:", err);
        res.status(500).send("Could not load update data.");
    }
});

app.get('/blacklist', (req, res) => {
    const ip = getClientIp(req);
    const blacklist = loadData(BLACKLIST_FILE);
    const blacklisted = blacklist.find(entry => entry.type === 'ip' && entry.value === ip);

    if (!blacklisted) return res.redirect('/');

    const isPermanent = blacklisted.expiresAt === 'permanent';
    const expiresAt = !isPermanent ? new Date(blacklisted.expiresAt).getTime() : null;

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <title>Access Denied</title>
            <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono&display=swap" rel="stylesheet">
            <style>
                body {
                    margin: 0;
                    padding: 0;
                    font-family: 'JetBrains Mono', monospace;
                    background: linear-gradient(135deg, #1f1c2c, #928dab);
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    color: white;
                    overflow: hidden;
                }
                .container {
                    background: rgba(0, 0, 0, 0.6);
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 0 20px rgba(255, 0, 0, 0.4);
                    text-align: center;
                    animation: fadeIn 1s ease-out;
                    max-width: 90%;
                    width: 400px;
                }
                h1 {
                    color: #ff6b6b;
                    margin-bottom: 10px;
                }
                p {
                    margin: 10px 0;
                    font-size: 1rem;
                }
                .timer {
                    font-weight: bold;
                    color: #f1c40f;
                }
                .discord-icon {
                    position: fixed;
                    bottom: 20px;
                    right: 20px;
                    width: 60px;
                    height: 60px;
                    cursor: pointer;
                    transition: transform 0.3s ease-in-out;
                    filter: drop-shadow(0 0 10px rgba(255, 255, 255, 0.5));
                    border-radius: 20%;
                }
                .discord-icon:hover {
                    transform: scale(1.1);
                }
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(20px); }
                    to { opacity: 1; transform: translateY(0); }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Access Denied</h1>
                <p><strong>Reason:</strong> ${blacklisted.reason || 'Tried to bypass the key system'}</p>
                <p><strong>Blacklist ID:</strong> ${blacklisted.blacklistId}</p>
                ${
                    isPermanent
                        ? `<p><strong>Duration:</strong> Permanent</p>`
                        : `<p><strong>Time Remaining:</strong> <span class="timer" id="timer">Calculating...</span></p>
                            <script>
                                const end = ${expiresAt};
                                const updateTimer = () => {
                                    const now = new Date().getTime();
                                    let diff = end - now;

                                    if (diff <= 0) {
                                        document.getElementById("timer").innerText = "Expired";
                                        return;
                                    }

                                    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
                                    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                                    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
                                    const seconds = Math.floor((diff % (1000 * 60)) / 1000);

                                    document.getElementById("timer").innerText =
                                        \`\${days}d \${hours}h \${minutes}m \${seconds}s\`;
                                };
                                setInterval(updateTimer, 1000);
                                updateTimer();
                            </script>`
                }
            </div>
            <img src="https://cdn.discordapp.com/embed/avatars/0.png" class="discord-icon" onclick="window.location.href='https://discord.gg/WPR9sJfZaJ'" alt="Discord">
        </body>
        </html>
    `);
});

app.get('/key-details', (req, res) => {
  const { key } = req.query;
  const keys = loadData(KEYS_FILE);
  const foundKey = keys.find(entry => entry.key === key);

  const sharedCSS = `
    <style>
      :root {
        --primary: #00ffd5;
        --secondary: #1e1e2f;
        --hover-bg: #3e3e5e;
        --glass-bg: rgba(255, 255, 255, 0.05);
        --shadow: rgba(255, 255, 255, 0.1);
      }

      body {
        margin: 0;
        font-family: 'Orbitron', sans-serif;
        background: linear-gradient(135deg, #0a0a0f, #1c1c24);
        color: white;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        overflow: hidden;
      }

      canvas#bg {
        position: fixed;
        top: 0;
        left: 0;
        z-index: 0;
      }

      .container {
        background: var(--glass-bg);
        backdrop-filter: blur(20px);
        border-radius: 20px;
        padding: 40px 30px;
        box-shadow: 0 0 30px var(--shadow);
        text-align: center;
        z-index: 2;
        max-width: 600px;
        width: 90%;
        animation: fadeInUp 1s ease;
      }

      h1 {
        font-size: 2rem;
        margin-bottom: 30px;
        color: var(--primary);
        text-shadow: 0 0 10px rgba(0, 255, 213, 0.4);
      }

      .key-box {
        font-size: 1rem;
        background: rgba(0, 0, 0, 0.4);
        border-radius: 12px;
        padding: 20px;
        line-height: 1.6;
        margin-bottom: 30px;
        box-shadow: 0 0 20px rgba(0, 255, 213, 0.1);
      }

      #timer {
        color: var(--primary);
        font-weight: 600;
      }

      .button-link {
        display: inline-block;
        background: var(--secondary);
        color: white;
        padding: 14px 25px;
        border-radius: 10px;
        text-decoration: none;
        font-size: 16px;
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
        margin: 10px 8px;
      }

      .button-link::before {
        content: '';
        position: absolute;
        top: 50%;
        left: -100%;
        width: 300%;
        height: 300%;
        background: radial-gradient(circle at center, rgba(0, 255, 213, 0.2), transparent 70%);
        transform: translateY(-50%);
        transition: all 0.5s ease;
        pointer-events: none;
      }

      .button-link:hover::before {
        left: 100%;
      }

      .button-link:hover {
        background: var(--hover-bg);
        transform: scale(1.05);
      }

      .discord-icon {
        position: fixed;
        bottom: 20px;
        right: 20px;
        width: 60px;
        height: 60px;
        cursor: pointer;
        z-index: 10;
        filter: drop-shadow(0 0 10px rgba(0,255,213,0.5));
        transition: transform 0.3s ease;
        border-radius: 20%;
      }

      .discord-icon:hover {
        transform: scale(1.1) rotate(10deg);
      }

      @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(30px); }
        to { opacity: 1; transform: translateY(0); }
      }

      @media (max-width: 600px) {
        h1 { font-size: 1.5rem; }
        .key-box { font-size: 0.95rem; }
      }
    </style>
  `;

  const particleScript = `
    <script>
      const canvas = document.getElementById('bg');
      const ctx = canvas.getContext('2d');
      let width, height, particles = [];

      function resize() {
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = width;
        canvas.height = height;
      }

      class Particle {
        constructor() {
          this.x = Math.random() * width;
          this.y = Math.random() * height;
          this.vx = (Math.random() - 0.5) * 0.5;
          this.vy = (Math.random() - 0.5) * 0.5;
          this.radius = Math.random() * 2 + 1;
          this.alpha = Math.random() * 0.5 + 0.2;
        }

        draw() {
          ctx.beginPath();
          ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(0, 255, 213, ' + this.alpha + ')';
          ctx.fill();
        }

        update() {
          this.x += this.vx;
          this.y += this.vy;
          if (this.x > width || this.x < 0) this.vx *= -1;
          if (this.y > height || this.y < 0) this.vy *= -1;
          this.draw();
        }
      }

      function initParticles() {
        particles = [];
        const count = Math.floor(width / 10);
        for (let i = 0; i < count; i++) particles.push(new Particle());
      }

      function animate() {
        ctx.clearRect(0, 0, width, height);
        particles.forEach(p => p.update());
        requestAnimationFrame(animate);
      }

      window.addEventListener('resize', () => {
        resize();
        initParticles();
      });

      resize();
      initParticles();
      animate();
    </script>
  `;

  if (!foundKey) {
    return res.status(404).send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Key Not Found</title>
        <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500&display=swap" rel="stylesheet">
        ${sharedCSS}
      </head>
      <body>
        <canvas id="bg"></canvas>
        <div class="container">
          <h1>Key Not Found</h1>
          <div class="key-box">The key does not exist or has expired.</div>
          <a href="/key-info" class="button-link">⬅ Go Back</a>
        </div>
        <img src="https://cdn.discordapp.com/embed/avatars/0.png" class="discord-icon" onclick="window.location.href='https://discord.gg/We4FtdFD2D'" alt="Discord">
        ${particleScript}
      </body>
      </html>
    `);
  }

  const timeLeft = foundKey.expiresAt === 'permanent' ? 'permanent' : foundKey.expiresAt - Date.now();

  return res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Key Details</title>
      <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500&display=swap" rel="stylesheet">
      ${sharedCSS}
    </head>
    <body>
      <canvas id="bg"></canvas>
      <div class="container">
        <h1>Key Details</h1>
        <div class="key-box">
          <p><strong>Key:</strong> ${foundKey.key}</p>
          <p><strong>Expires In:</strong> <span id="timer">${timeLeft === 'permanent' ? 'PERMANENT' : ''}</span></p>
          <p><strong>Used By:</strong> ${foundKey.usedBy.length > 0 ? foundKey.usedBy.join(', ') : 'No users currently.'}</p>
        </div>
        <a href="/key-info" class="button-link">⬅ Go Back</a>
        <a class="button-link" onclick="unbind()">🔓 Unbind Key</a>
      </div>

      <img src="https://cdn.discordapp.com/embed/avatars/0.png" class="discord-icon" onclick="window.location.href='https://discord.gg/We4FtdFD2D'" alt="Discord">

      <script>
        const expiry = ${timeLeft === 'permanent' ? 0 : Date.now() + timeLeft};
        const timer = document.getElementById('timer');
        const key = "${foundKey.key}";

        function updateTimer() {
          if (expiry === 0) return;
          const now = Date.now();
          const diff = expiry - now;

          if (diff <= 0) {
            timer.textContent = "EXPIRED";
            clearInterval(interval);
            return;
          }

          const d = Math.floor(diff / (1000 * 60 * 60 * 24));
          const h = Math.floor((diff / (1000 * 60 * 60)) % 24);
          const m = Math.floor((diff / (1000 * 60)) % 60);
          const s = Math.floor((diff / 1000) % 60);
          timer.textContent = \`\${d}d \${h}h \${m}m \${s}s\`;
        }

        const interval = setInterval(updateTimer, 1000);
        updateTimer();

        function unbind() {
          fetch('/unbind-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key })
          })
          .then(res => res.json())
          .then(data => {
            alert(data.message);
            location.reload();
          });
        }
      </script>

      ${particleScript}
    </body>
    </html>
  `);
});

app.post('/unbind-key', express.json(), (req, res) => {
  const { key } = req.body;
  const keys = loadData(KEYS_FILE);

  const foundKey = keys.find(k => k.key === key);
  if (!foundKey) {
    return res.json({ success: false, message: 'Key not found.' });
  }

  foundKey.usedBy = [];
  foundKey.inUse = false;
  saveData(KEYS_FILE, keys);

  res.json({ success: true, message: 'All users unbound from this key.' });
});

app.post('/addtime', express.json(), (req, res) => {
    const { key, hours } = req.body;
    const keys = loadData(KEYS_FILE);

    const foundKey = keys.find(k => k.key === key);
    if (!foundKey) {
        return res.status(404).json({ error: 'Key not found.' });
    }

    foundKey.expiresAt += parseInt(hours) * 60 * 60 * 1000;
    saveData(KEYS_FILE, keys);
    res.json({ success: true, message: `Added ${hours} hours to the key.` });
});

app.post('/removetime', express.json(), (req, res) => {
  const { key, hours } = req.body;
  const keys = loadData(KEYS_FILE);

  const foundKey = keys.find(k => k.key === key);
  if (!foundKey) {
    return res.status(404).json({ error: 'Key not found.' });
  }

  if (foundKey.expiresAt === 'permanent') {
    return res.status(400).json({ error: 'Cannot remove time from a permanent key.' });
  }

  const timeToRemove = parseInt(hours) * 60 * 60 * 1000;
  foundKey.expiresAt -= timeToRemove;

  if (foundKey.expiresAt < Date.now()) {
    foundKey.expired = true;
  }

  saveData(KEYS_FILE, keys);
  res.json({ success: true, message: `Removed ${hours} hour(s) from the key.` });
});

app.get('/script-info', (req, res) => {
  res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>BSMT Hub | Script Info</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@500;600&display=swap" rel="stylesheet">
    <style>
      :root {
        --primary: #00ffd5;
        --bg-dark: #0a0a0f;
        --bg-darker: #1c1c24;
        --card-bg: rgba(255, 255, 255, 0.04);
        --button-bg: #1e1e2f;
        --button-hover: #32324a;
        --text-glow: rgba(0, 255, 213, 0.2);
      }

      body {
        margin: 0;
        font-family: 'Inter', sans-serif;
        background: linear-gradient(135deg, var(--bg-dark), var(--bg-darker));
        color: white;
        display: flex;
        justify-content: center;
        align-items: flex-start;
        min-height: 100vh;
        overflow-x: hidden;
      }

      canvas#bg {
        position: fixed;
        top: 0;
        left: 0;
        z-index: 0;
      }

      .container {
        margin-top: 80px;
        padding: 40px 32px;
        background: var(--card-bg);
        backdrop-filter: blur(16px);
        border-radius: 16px;
        box-shadow: 0 0 20px rgba(0,0,0,0.2);
        text-align: center;
        z-index: 1;
        max-width: 800px;
        width: 100%;
        animation: fadeInUp 0.8s ease;
      }

      h1 {
        font-size: 1.9rem;
        font-weight: 600;
        margin-bottom: 24px;
        color: var(--primary);
      }

      .code-container {
        background: #12121a;
        border-radius: 10px;
        padding: 16px;
        color: var(--primary);
        font-weight: 600;
        font-size: 0.95rem;
        user-select: all;
        cursor: pointer;
        margin-bottom: 16px;
        word-break: break-word;
        box-shadow: 0 0 8px var(--text-glow);
      }

      button, .go-back, .games-list button {
        font-family: 'Inter', sans-serif;
        background: var(--button-bg);
        color: white;
        border: none;
        padding: 12px 22px;
        font-size: 0.95rem;
        font-weight: 500;
        border-radius: 10px;
        cursor: pointer;
        transition: all 0.3s ease;
        margin: 6px;
      }

      button:hover, .go-back:hover, .games-list button:hover {
        background: var(--button-hover);
        transform: scale(1.03);
      }

      h2 {
        margin-top: 32px;
        font-size: 1.3rem;
        font-weight: 600;
      }

      .games-list {
        display: flex;
        flex-wrap: wrap;
        justify-content: center;
        gap: 10px;
        margin-top: 20px;
      }

      .go-back {
        margin-top: 24px;
        display: inline-block;
        text-decoration: none;
      }

      .discord-icon {
        position: fixed;
        bottom: 20px;
        right: 20px;
        width: 60px;
        height: 60px;
        cursor: pointer;
        z-index: 10;
        filter: drop-shadow(0 0 8px rgba(0,255,213,0.5));
        transition: transform 0.3s ease;
        border-radius: 20%;
      }

      .discord-icon:hover {
        transform: scale(1.08);
      }

      @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(30px); }
        to { opacity: 1; transform: translateY(0); }
      }

      @media (max-width: 600px) {
        .container {
          padding: 30px 20px;
        }

        .games-list {
          flex-direction: column;
        }

        h1 {
          font-size: 1.5rem;
        }
      }
    </style>
  </head>
  <body>

    <canvas id="bg"></canvas>

    <div class="container">
      <h1>Script Info</h1>
      <p style="margin-bottom: 12px;">Click below to copy</p>
      <div class="code-container" onclick="copyScript()">loadstring(game:HttpGet("https://thebasement.ink/BSMT"))()</div>
      <button onclick="copyScript()">Copy Script</button>

      <h2>Supported Games</h2>
      <div class="games-list">
        <button onclick="window.location.href='https://www.roblox.com/games/8689257920/Life-in-Prison'">Life in Prison</button>
        <button onclick="window.location.href='https://www.roblox.com/games/16792181861/SL-PRISON'">SL Prison</button>
        <button onclick="window.location.href='https://www.roblox.com/games/4639625707/Nighthawk-War-Tycoon'">War Tycoon</button>
        <button onclick="window.location.href='https://www.roblox.com/games/16732694052/Fisch-ATLANTIS'">Fisch</button>
        <button onclick="window.location.href='https://www.roblox.com/games/2753915549/Blox-Fruits'">Bloxfruit</button>
        <button onclick="window.location.href='https://www.roblox.com/games/13127800756/Arm-Wrestle-Simulator'">Arm Wrestling</button>
        <button onclick="window.location.href='https://www.roblox.com/games/1537690962/Bee-Swarm-Simulator'">Bee Swarm</button>
        <button onclick="window.location.href='https://www.roblox.com/games/116495829188952/Dead-Rails-Alpha'">Dead Rails</button>
        <button onclick="window.location.href='https://www.roblox.com/home'">Universal Script</button>
      </div>

      <a href="/" class="go-back">⬅ Return Home</a>
    </div>

    <img src="https://cdn.discordapp.com/embed/avatars/0.png" class="discord-icon" onclick="window.location.href='https://discord.gg/We4FtdFD2D'" alt="Discord">

    <script>
      const canvas = document.getElementById('bg');
      const ctx = canvas.getContext('2d');
      let width, height;
      let particles = [];

      function resize() {
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = width;
        canvas.height = height;
      }

      class Particle {
        constructor() {
          this.x = Math.random() * width;
          this.y = Math.random() * height;
          this.vx = (Math.random() - 0.5) * 0.5;
          this.vy = (Math.random() - 0.5) * 0.5;
          this.radius = Math.random() * 2 + 1;
          this.alpha = Math.random() * 0.5 + 0.2;
        }

        draw() {
          ctx.beginPath();
          ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(0, 255, 213, ' + this.alpha + ')';
          ctx.fill();
        }

        update() {
          this.x += this.vx;
          this.y += this.vy;
          if (this.x > width || this.x < 0) this.vx *= -1;
          if (this.y > height || this.y < 0) this.vy *= -1;
          this.draw();
        }
      }

      function initParticles() {
        particles = [];
        const count = Math.floor(width / 10);
        for (let i = 0; i < count; i++) particles.push(new Particle());
      }

      function animate() {
        ctx.clearRect(0, 0, width, height);
        particles.forEach(p => p.update());
        requestAnimationFrame(animate);
      }

      window.addEventListener('resize', () => {
        resize();
        initParticles();
      });

      resize();
      initParticles();
      animate();

      function copyScript() {
        const text = "loadstring(game:HttpGet("https://thebasement.ink/BSMT"))()";
        navigator.clipboard.writeText(text)
          .then(() => alert("Copied!"))
          .catch(err => console.error("Copy failed:", err));
      }
    </script>
  </body>
  </html>
  `);
});

app.get("/redirect-to-linkvertise", (req, res) => {
    const ip = getClientIp(req);
    const { step } = req.query;

    const validSteps = {
        "checkpoint2": OBFUSCATED_ENDPOINTS.checkpoint2,
        "key-generated": OBFUSCATED_ENDPOINTS.keyGenerated
    };

    if (!validSteps[step]) {
        console.log(`🚨 ERROR: Invalid step "${step}" requested by IP ${ip}`);
        return res.redirect("/");
    }

    console.log(`✅ Redirecting ${ip} to Linkvertise for ${step}`);
    const linkvertiseUrl = `https://link-center.net/1203734/the-basement-key1`;
    res.redirect(linkvertiseUrl);
});

function antiBypass(req, res, next) {
    const ip = getClientIp(req);
    const progress = loadData(PROGRESS_FILE);
    const userProgress = progress.find(entry => entry.ip === ip);

    const requiredCheckpoints = {
        [`/${OBFUSCATED_ENDPOINTS.checkpoint2}`]: ["redirect-to-linkvertise"],
        [`/${OBFUSCATED_ENDPOINTS.keyGenerated}`]: ["redirect-to-linkvertise", OBFUSCATED_ENDPOINTS.checkpoint2]
    };

    // If no progress exists for the user, blacklist them
    if (!userProgress) {
        console.log(`🚨 BLACKLISTING ${ip}: No progress found.`);
        blacklistIp(ip, "Bypassed Linkvertise");
        return res.redirect("/blacklist");
    }

    // Check if the user has completed all required checkpoints
    const hasAllCheckpoints = requiredCheckpoints[req.path].every(cp => userProgress.checkpoints.includes(cp));

    if (!hasAllCheckpoints) {
        console.log(`🚨 BLACKLISTING ${ip}: Attempted to access ${req.path} without completing previous steps.`);
        blacklistIp(ip, "Bypassed Linkvertise");
        return res.redirect("/blacklist");
    }

    next();
}

app.get(`/${OBFUSCATED_ENDPOINTS.checkpoint2}`, (req, res) => {
  const ip = getClientIp(req);
  const { referer } = req.headers;
  const progress = loadData(PROGRESS_FILE);
  const userProgress = progress.find(entry => entry.ip === ip);

  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Checkpoint 2 | BSMT Hub</title>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@500;600&display=swap" rel="stylesheet">
      <style>
        :root {
          --primary: #00ffd5;
          --secondary: #1e1e2f;
          --hover-bg: #3e3e5e;
          --glass-bg: rgba(255, 255, 255, 0.05);
          --shadow: rgba(255, 255, 255, 0.1);
        }

        body {
          margin: 0;
          font-family: 'Inter', sans-serif;
          background: linear-gradient(135deg, #0a0a0f, #1c1c24);
          color: white;
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
          text-align: center;
          overflow: hidden;
        }

        .container {
          background: var(--glass-bg);
          backdrop-filter: blur(20px);
          padding: 40px 32px;
          border-radius: 16px;
          box-shadow: 0 0 30px var(--shadow);
          animation: fadeInUp 0.8s ease;
          z-index: 2;
        }

        h1 {
          font-size: 1.8rem;
          margin-bottom: 24px;
          color: var(--primary);
          font-weight: 600;
        }

        a#linkvertise {
          display: inline-block;
          padding: 14px 28px;
          background: var(--secondary);
          border-radius: 10px;
          color: white;
          font-size: 1rem;
          font-weight: 500;
          text-decoration: none;
          transition: all 0.3s ease;
          box-shadow: 0 0 15px rgba(0, 255, 213, 0.2);
        }

        a#linkvertise:hover {
          background: var(--hover-bg);
          transform: scale(1.05);
        }

        .discord-icon {
          position: fixed;
          bottom: 20px;
          right: 20px;
          width: 60px;
          height: 60px;
          cursor: pointer;
          z-index: 10;
          filter: drop-shadow(0 0 10px rgba(0,255,213,0.5));
          transition: transform 0.3s ease;
          border-radius: 20%;
        }

        .discord-icon:hover {
          transform: scale(1.1) rotate(10deg);
        }

        @keyframes fadeInUp {
          from { opacity: 0; transform: translateY(30px); }
          to { opacity: 1; transform: translateY(0); }
        }

        @media (max-width: 600px) {
          h1 {
            font-size: 1.5rem;
          }

          a#linkvertise {
            font-size: 0.95rem;
            padding: 12px 20px;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Checkpoint 2</h1>
        <a href="https://link-target.net/1203734/key" id="linkvertise">Complete Checkpoint 2</a>
      </div>
      <img src="https://cdn.discordapp.com/embed/avatars/0.png" class="discord-icon" onclick="window.location.href='https://discord.gg/We4FtdFD2D'" alt="Discord">
    </body>
    </html>
  `;

  if (userProgress && userProgress.checkpoints.includes(OBFUSCATED_ENDPOINTS.checkpoint2)) {
    return res.send(html);
  }

  if (!referer || !referer.includes("linkvertise.com")) {
    console.log(`🚨 BLACKLISTING ${ip}: Tried to access Checkpoint2 without Linkvertise.`);
    blacklistIp(ip, "Bypassed Linkvertise");
    return res.redirect("/blacklist");
  }

  saveProgress(ip, OBFUSCATED_ENDPOINTS.checkpoint2);
  return res.send(html);
});

app.get('/bypassbozo', (req, res) => {
    const ip = getClientIp(req);
    const blacklist = loadData(BLACKLIST_FILE);

    // Check if IP is already blacklisted
    const isAlreadyBlacklisted = blacklist.some(entry => entry.type === 'ip' && entry.value === ip);
    if (!isAlreadyBlacklisted) {
        blacklist.push({ type: 'ip', value: ip, expiry: 'permanent' });
        saveData(BLACKLIST_FILE, blacklist);
    }

    res.sendFile(path.join(__dirname, 'public', 'bypassbozo.html'));
});

app.get(`/${OBFUSCATED_ENDPOINTS.keyGenerated}`, (req, res) => {
  const ip = getClientIp(req);
  let keys = loadData(KEYS_FILE);
  let progress = loadData(PROGRESS_FILE);
  let userProgress = progress.find(entry => entry.ip === ip);

  if (!userProgress || !userProgress.checkpoints.includes(OBFUSCATED_ENDPOINTS.checkpoint2)) {
    console.log(` BLACKLISTING ${ip}: Accessed Key-Generated without completing Checkpoint2.`);
    blacklistIp(ip, "Bypassed Checkpoint2");
    return res.redirect("/blacklist");
  }

  let existingKey = keys.find(key => key.ip === ip && !key.expired);

  if (existingKey && existingKey.expiresAt !== "permanent" && Date.now() > existingKey.expiresAt) {
    console.log(`⏳ Key expired for ${ip}, resetting progress.`);
    existingKey.expired = true;
    saveData(KEYS_FILE, keys);
    resetProgress(ip);
    return res.redirect("/");
  }

  if (!existingKey) {
    console.log(`🟢 Generating new key for ${ip}`);
    existingKey = createKey(ip);
    keys.push(existingKey);
    saveData(KEYS_FILE, keys);
  }

  // Save progress
  saveProgress(ip, OBFUSCATED_ENDPOINTS.keyGenerated);

  const timeLeft = existingKey.expiresAt === "permanent" ? "permanent" : existingKey.expiresAt - Date.now();

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Your Generated Key</title>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@500;600&display=swap" rel="stylesheet">
      <style>
        :root {
          --primary: #00ffd5;
          --secondary: #1e1e2f;
          --hover-bg: #3e3e5e;
          --glass-bg: rgba(255, 255, 255, 0.05);
          --shadow: rgba(255, 255, 255, 0.1);
        }

        body {
          margin: 0;
          font-family: 'Inter', sans-serif;
          background: linear-gradient(135deg, #0a0a0f, #1c1c24);
          color: white;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          padding: 20px;
          text-align: center;
          overflow: hidden;
        }

        h1 {
          font-size: 1.9rem;
          font-weight: 600;
          color: var(--primary);
          margin-bottom: 20px;
        }

        .key-box {
          background: #12121a;
          border-radius: 12px;
          padding: 16px 28px;
          font-size: 1.2rem;
          color: var(--primary);
          font-weight: 600;
          box-shadow: 0 0 15px rgba(0,255,213,0.1);
          margin-bottom: 15px;
          animation: fadeInUp 0.8s ease;
        }

        #timer {
          font-size: 1rem;
          font-weight: 500;
          color: #00ffae;
          text-shadow: 0 0 6px rgba(0, 255, 213, 0.3);
        }

        .btn {
          margin-top: 16px;
          padding: 12px 24px;
          border: none;
          border-radius: 10px;
          font-size: 0.95rem;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.3s ease;
        }

        .reset-btn {
          background: #ff4d4d;
          color: white;
          box-shadow: 0 0 10px rgba(255, 77, 77, 0.4);
        }

        .reset-btn:hover {
          background: #e63946;
          transform: scale(1.05);
        }

        .home-btn {
          background: var(--secondary);
          color: white;
          margin-left: 10px;
        }

        .home-btn:hover {
          background: var(--hover-bg);
          transform: scale(1.05);
        }

        @keyframes fadeInUp {
          from { opacity: 0; transform: translateY(30px); }
          to { opacity: 1; transform: translateY(0); }
        }

        @media (max-width: 600px) {
          .btn {
            width: 100%;
            margin: 10px 0 0;
          }

          .home-btn {
            margin-left: 0;
          }
        }
      </style>
    </head>
    <body>
      <h1>Your Generated Key</h1>
      <div class="key-box">${existingKey.key}</div>
      <p>Expires in: <span id="timer">${timeLeft === "permanent" ? "PERMANENT" : ""}</span></p>
      
      <div>
        <button class="btn reset-btn" onclick="window.location.href='/reset-key'">Reset Key</button>
        <button class="btn home-btn" onclick="window.location.href='/'">Go Home</button>
      </div>

      <script>
        const expiry = ${timeLeft === "permanent" ? 0 : Date.now() + timeLeft};
        const timerElement = document.getElementById("timer");

        if (expiry > 0) {
          const interval = setInterval(() => {
            const now = Date.now();
            const distance = expiry - now;

            if (distance <= 0) {
              clearInterval(interval);
              timerElement.innerHTML = "EXPIRED";
              setTimeout(() => window.location.href = "/", 1000);
              return;
            }

            const hours = Math.floor((distance / (1000 * 60 * 60)) % 24);
            const minutes = Math.floor((distance / (1000 * 60)) % 60);
            const seconds = Math.floor((distance / 1000) % 60);

            timerElement.innerHTML = \`\${hours}h \${minutes}m \${seconds}s\`;
          }, 1000);
        }
      </script>
    </body>
    </html>
  `);
});

app.post("/delete-key", express.json(), (req, res) => {
    const { key } = req.body;
    let keys = loadData(KEYS_FILE);

    const index = keys.findIndex(k => k.key === key);
    if (index === -1) {
        return res.status(404).json({ success: false, message: "Key not found." });
    }

    resetProgress(keys[index].ip); 
    keys.splice(index, 1);
    saveData(KEYS_FILE, keys);

    res.json({ success: true, message: `Key "${key}" has been deleted.` });
});

app.get("/reset-key", (req, res) => {
    const ip = getClientIp(req);
    let keys = loadData(KEYS_FILE);

    keys = keys.filter(key => key.ip !== ip);
    saveData(KEYS_FILE, keys);

    resetProgress(ip);

    res.redirect("/");
});

app.get('/verify-key', (req, res) => {
    const { key, playerName } = req.query;
    const ip = getClientIp(req);
    const blacklistCheck = isBlacklisted(ip, playerName);

    if (blacklistCheck.blacklisted) {
        return res.json({ valid: false, message: blacklistCheck.message });
    }

    const keys = loadData(KEYS_FILE);
    const foundKey = keys.find(k => k.key === key && !k.expired);

    // Add the expiration check here for 'permanent' keys
    if (foundKey) {
        if (foundKey.expiresAt !== 'permanent' && Date.now() > foundKey.expiresAt) {
            foundKey.expired = true;
            saveData(KEYS_FILE, keys);
            return res.json({ valid: false, message: "The key has expired." });
        }

        // Max users check and other code remain the same
        if (foundKey.usedBy.length >= foundKey.maxUsers) {
            return res.json({ valid: false, message: "Cheia a atins limita de utilizatori." });
        }

        if (!foundKey.usedBy.includes(playerName)) {
            foundKey.usedBy.push(playerName);
            foundKey.inUse = true;
            saveData(KEYS_FILE, keys);
        }

        res.json({ valid: true, message: "Cheia este validă." });
    } else {
        res.json({ valid: false, message: "Cheia nu este validă sau a expirat." });
    }
});

app.post('/admin/clear-blacklist', (req, res) => {
    saveData(BLACKLIST_FILE, []); 
    res.redirect('/admin?access_code=buratiocadminboscotos'); 
});

app.post('/admin/create-permanent-key', (req, res) => {
    const { key } = req.body;
    const keys = loadData(KEYS_FILE);

    const newKey = {
        key: key,
        ip: 'admin',
        maxUsers: 2, 
        createdAt: Date.now(),
        expiresAt: 'permanent',
        expired: false,
        inUse: false,
        usedBy: []
    };

    keys.push(newKey);
    saveData(KEYS_FILE, keys);
    res.send('Permanent key created successfully.');
});

app.get('/admin', adminsg, (req, res) => {
    removeExpiredKeys();

    const keys = loadData(KEYS_FILE);
    const blacklist = loadData(BLACKLIST_FILE);

    let keysHtml = keys.map(key => `
        <tr>
            <td>${key.key}</td>
            <td>${key.ip}</td>
            <td><span id="timer-${key.key}">${key.expiresAt !== 'permanent' ? moment(key.expiresAt).fromNow() : 'Permanent'}</span></td>
            <td>${key.inUse ? key.usedBy.join(', ') : 'false'}</td>
            <td>${key.maxUsers}</td>
            <td>
                <form action="/admin/delete-key" method="POST" style="display:inline;">
                    <input type="hidden" name="key" value="${key.key}">
                    <button type="submit">Delete</button>
                </form>
                <form action="/admin/add-time" method="POST" style="display:inline;">
                    <input type="hidden" name="key" value="${key.key}">
                    <input type="number" name="hours" placeholder="Hours" required>
                    <button type="submit">Add Time</button>
                </form>
            </td>
        </tr>
    `).join('');

    let blacklistHtml = blacklist.map(entry => `
    <tr>
        <td>${entry.type === 'ip' ? 'IP' : 'Player'}</td>
        <td>${entry.value}</td>
        <td>${entry.expiry === 'permanent' ? 'Permanent' : moment(entry.expiry).format('LLLL')}</td>
        <td>${entry.blacklistId || 'N/A'}</td> <!-- Afișează blacklistId sau N/A -->
        <td>
            <form action="/admin/remove-blacklist" method="POST" style="display:inline;">
                <input type="hidden" name="value" value="${entry.value}">
                <button type="submit">Remove</button>
            </form>
            <form action="/admin/modify-blacklist-time" method="POST" style="display:inline;">
                <input type="hidden" name="value" value="${entry.value}">
                <input type="number" name="hours" placeholder="Hours" required>
                <button type="submit">Add/Reduce Time</button>
            </form>
        </td>
    </tr>
`).join('');

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Page</title>
            <style>
                body {
                    background: linear-gradient(to bottom, #003366, white);
                    font-family: Arial, sans-serif;
                    margin: 20px;
                }
                h1 {
                    color: #333;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }
                th, td {
                    padding: 10px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }
                th {
                    background-color: #003d80;
                    color: white;
                }
                button {
                    background-color: #0056b3;
                    color: white;
                    padding: 5px 10px;
                    border: none;
                    border-radius: 5px;
                    cursor: pointer;
                }
                button:hover {
                    background-color: #003d80;
                }
                input[type="number"], input[type="text"] {
                    padding: 5px;
                    border-radius: 5px;
                    border: 1px solid #ddd;
                    margin-right: 10px;
                }
            </style>
        </head>
        <body>
            <h1>Admin Page</h1>
            <input type="text" id="search-bar" placeholder="Search by key, IP, or player name" style="width: 100%; padding: 10px; border-radius: 5px; border: 1px solid #ddd; margin-bottom: 20px;">
            <table id="keys-table">
                <tr>
                    <th>Key</th>
                    <th>IP</th>
                    <th>Expires At</th>
                    <th>In Use</th>
                    <th>Max Users</th>
                    <th>Actions</th>
                </tr>
                ${keysHtml}
            </table>
            <h2>Blacklist</h2>
            <table id="blacklist-table">
                <tr>
                    <th>Type</th>
                    <th>Value</th>
                    <th>Expiry</th>
                    <th>ID</th>
                    <th>Actions</th>
                </tr>
                ${blacklistHtml}
            </table>
            <h2>Add to Blacklist</h2>
            <form id="blacklist-form">
                <select id="blacklist-type" required>
                    <option value="player">Player</option>
                    <option value="ip">IP</option>
                </select>
                <input type="text" id="blacklist-value" placeholder="Player Name or IP" required>
                <input type="text" id="blacklist-duration" placeholder="Duration (hours or 'permanent')" required>
                <button type="submit">Add to Blacklist</button>
            </form>
            <h2>Delete All Keys</h2>
            <form action="/admin/delete-all-keys" method="POST">
                <button type="submit">Delete All Keys</button>
            </form>
            <h2>Create Custom Key</h2>
            <form action="/admin/create-custom-key" method="POST">
                <input type="text" name="key" placeholder="Custom Key" required>
                <input type="number" name="duration" placeholder="Duration (hours)" required>
                <input type="number" name="maxUsers" placeholder="Max Users" required>
                <button type="submit">Create Custom Key</button>
            </form>
            <h2>Create Permanent Key</h2>
            <form action="/admin/create-permanent-key" method="POST">
                <input type="text" name="key" placeholder="Permanent Key Name" required>
                <button type="submit">Create Permanent Key</button>
            </form>
            <h2>Add Time to All Keys</h2>
            <form action="/admin/add-time-all" method="POST">
                <input type="number" name="hours" placeholder="Hours to Add" required>
                <button type="submit">Add Time to All Keys</button>
            </form>
            <h2>Send Notification</h2>
            <form id="notification-form">
                <input type="text" id="notification-message" placeholder="Message to Send" required>
                <button type="submit">Send Notification</button>
            </form>
            <h2>Send Kick Message</h2>
            <form id="kick-form">
                <input type="text" id="kick-message" placeholder="Kick Message" required>
                <button type="submit">Send Kick</button>
            </form>
            <h2>Unblacklist Everyone</h2>
            <form action="/admin/clear-blacklist" method="POST">
                <button type="submit">Unblacklist Everyone</button>
            </form>
            <script>
                document.getElementById('blacklist-form').addEventListener('submit', function(event) {
                    event.preventDefault();
                    const type = document.getElementById('blacklist-type').value;
                    const value = document.getElementById('blacklist-value').value;
                    const duration = document.getElementById('blacklist-duration').value;
                    fetch('/admin/add-blacklist', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: new URLSearchParams({
                            'type': type,
                            'value': value,
                            'duration': duration
                        })
                    }).then(response => response.text()).then(data => {
                        alert(data);
                        location.reload();
                    });
                });

                document.getElementById('notification-form').addEventListener('submit', function(event) {
                    event.preventDefault();
                    const message = document.getElementById('notification-message').value;
                    fetch('/admin/send-notification', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: new URLSearchParams({
                            'message': message
                        })
                    }).then(response => response.text()).then(data => {
                        alert(data);
                        location.reload();
                    });
                });

                document.getElementById('kick-form').addEventListener('submit', function(event) {
                    event.preventDefault();
                    const message = document.getElementById('kick-message').value;
                    fetch('/admin/send-kick', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: new URLSearchParams({
                            'message': message
                        })
                    }).then(response => response.text()).then(data => {
                        alert(data);
                        location.reload();
                    });
                });

                document.getElementById('search-bar').addEventListener('input', function(event) {
                    const searchQuery = event.target.value.toLowerCase();
                    const rows = document.querySelectorAll('#keys-table tr:not(:first-child), #blacklist-table tr:not(:first-child)');
                    rows.forEach(row => {
                                            const key = row.cells[0]?.textContent.toLowerCase() || '';
                        const value = row.cells[1]?.textContent.toLowerCase() || '';
                        const usedBy = row.cells[3]?.textContent.toLowerCase() || '';
                        if (key.includes(searchQuery) || value.includes(searchQuery) || usedBy.includes(searchQuery)) {
                            row.style.display = '';
                        } else {
                            row.style.display = 'none';
                        }
                    });
                });

                // Setează timerele pentru chei în pagina de admin
                const keys = ${JSON.stringify(keys)};
                keys.forEach(key => {
                    const timerElement = document.getElementById('timer-' + key.key);
                    if (timerElement) {
                        const countDownDate = key.expiresAt !== 'permanent' ? new Date(key.expiresAt).getTime() : null;

                        if (countDownDate) {
                            const x = setInterval(function() {
                                const now = new Date().getTime();
                                const distance = countDownDate - now;

                                const days = Math.floor(distance / (1000 * 60 * 60 * 24));
                                const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                                const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                                const seconds = Math.floor((distance % (1000 * 60)) / 1000);

                                timerElement.innerHTML = days + "d " + hours + "h " + minutes + "m " + seconds + "s";

                                if (distance < 0) {
                                    clearInterval(x);
                                    timerElement.innerHTML = "EXPIRED";
                                    setTimeout(function() {
                                        location.reload();
                                    }, 1000); // Reîncarcă pagina pentru a actualiza cheile expirate
                                }
                            }, 1000);
                        } else {
                            timerElement.innerHTML = "Permanent";
                        }
                    }
                });
            </script>
        </body>
        </html>
    `);
});

function generateBlacklistId() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let id = '';
    for (let i = 0; i < 6; i++) {
        id += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return id;
}

// Adăugare pe blacklist cu ID unic
app.post('/admin/add-blacklist', (req, res) => {
    const { type, value, duration } = req.body;
    const blacklist = loadData(BLACKLIST_FILE);
    let expiry;

    if (duration.toLowerCase() === 'permanent') {
        expiry = 'permanent';
    } else {
        expiry = Date.now() + parseInt(duration) * 60 * 60 * 1000; // Durata în ore
    }

    // Verifică dacă există deja un cod pentru acest IP
    if (!blacklist.some(entry => entry.value === value)) {
        blacklist.push({
            type: type,
            value: value,
            expiry: expiry,
            blacklistId: generateBlacklistId() // Atribuie un cod unic
        });
    }

    saveData(BLACKLIST_FILE, blacklist);
    res.send('Added to blacklist successfully.');
});

app.post('/reset-all', (req, res) => {
    const adminCode = req.query.admin_code;
    
    if (adminCode !== 'buratiocadminboscotos') {
        return res.status(401).json({ error: "Unauthorized" });
    }

    saveData(BLACKLIST_FILE, []);
    saveData(PROGRESS_FILE, []);

    res.json({ success: true, message: "All data has been reset." });
});

app.post('/admin/remove-blacklist', (req, res) => {
    const { value } = req.body;
    let blacklist = loadData(BLACKLIST_FILE);
    blacklist = blacklist.filter(entry => entry.value !== value);
    saveData(BLACKLIST_FILE, blacklist);
    res.redirect('/admin?access_code=buratiocadminboscotos');
});

// Route pentru modificarea timpului pe blacklist
app.post('/admin/modify-blacklist-time', (req, res) => {
    const { value, hours } = req.body;
    const blacklist = loadData(BLACKLIST_FILE);
    const now = Date.now();

    const entry = blacklist.find(entry => entry.value === value);
    if (entry) {
        if (entry.expiry !== 'permanent') {
            entry.expiry = Math.max(now, entry.expiry) + parseInt(hours) * 60 * 60 * 1000;
        }
    }

    saveData(BLACKLIST_FILE, blacklist);
        res.redirect('/admin?access_code=buratiocadminboscotos');
});

// Route pentru ștergerea unei chei
app.post('/admin/delete-key', (req, res) => {
    const { key } = req.body;
    let keys = loadData(KEYS_FILE);
    keys = keys.filter(k => k.key !== key);
    saveData(KEYS_FILE, keys);
    res.redirect('/admin?access_code=buratiocadminboscotos');
});

// Route pentru ștergerea cheilor expirate
app.post('/admin/delete-expired-keys', (req, res) => {
    removeExpiredKeys();
    res.redirect('/admin?access_code=buratiocadminboscotos');
});

// Route pentru ștergerea tuturor cheilor
app.post('/admin/delete-all-keys', (req, res) => {
    removeAllKeys();
    res.redirect('/admin?access_code=buratiocadminboscotos');
});

// Route pentru crearea unei chei noi
app.post('/admin/create-key', (req, res) => {
    const ip = 'admin';
    createKey(ip);
    res.redirect('/admin?access_code=buratiocadminboscotos');
});

app.post('/admin/clear-blacklist', (req, res) => {
    saveData(BLACKLIST_FILE, []);
    res.redirect('/admin?access_code=buratiocadminboscotos');
});

app.post('/create-key', express.json(), (req, res) => {
    const { name, duration, maxUsers } = req.body;

    if (!name || !duration || !maxUsers) {
        return res.status(400).json({ error: "Missing required fields: name, duration, or maxUsers." });
    }

    const newKey = {
        key: name,
        ip: "admin",
        maxUsers: parseInt(maxUsers),
        createdAt: Date.now(),
        expiresAt: Date.now() + parseInt(duration),
        expired: false,
        inUse: false,
        usedBy: []
    };

    const keys = loadData(KEYS_FILE);
    keys.push(newKey);
    saveData(KEYS_FILE, keys);

    res.json({ success: true, key: newKey });
});

app.delete('/unblacklist/:blacklistId', (req, res) => {
    const { blacklistId } = req.params;

    const blacklist = loadData(BLACKLIST_FILE);
    const updatedBlacklist = blacklist.filter(entry => entry.blacklistId !== blacklistId);

    if (blacklist.length === updatedBlacklist.length) {
        return res.status(404).send('Blacklist ID not found.');
    }

    saveData(BLACKLIST_FILE, updatedBlacklist);
    res.status(200).send('Blacklist ID removed successfully.');
});

// Route pentru crearea unei chei personalizate
app.post('/admin/create-custom-key', (req, res) => {
    const { key, duration, maxUsers } = req.body;
    createCustomKey(key, duration, maxUsers);
    res.send('Custom key created successfully.');
});

// Route pentru trimiterea unei notificări
app.post('/admin/send-notification', (req, res) => {
    const { message } = req.body;
    const notifications = loadData(NOTIFICATIONS_FILE);

    notifications.push({ message, type: 'notification' });
    saveData(NOTIFICATIONS_FILE, notifications);
    res.send('Notification sent successfully.');
});

// Route pentru trimiterea unui kick
app.post('/admin/send-kick', (req, res) => {
    const { message } = req.body;
    const notifications = loadData(NOTIFICATIONS_FILE);

    notifications.push({ message, type: 'kick' });
    saveData(NOTIFICATIONS_FILE, notifications);
    res.send('Kick sent successfully.');
});

// Route pentru obținerea notificărilor active
app.get('/get-notifications', (req, res) => {
    const notifications = loadData(NOTIFICATIONS_FILE);
    res.json(notifications);
});

// Șterge notificările după ce au fost procesate
app.post('/clear-notifications', (req, res) => {
    saveData(NOTIFICATIONS_FILE, []);
    res.send('Notifications cleared.');
});

// Route pentru adăugarea timpului la toate cheile
app.post('/admin/add-time', (req, res) => {
    const { key, hours } = req.body;
    const keys = loadData(KEYS_FILE);
    const updatedKeys = keys.map(k => {
        if (k.key === key && !k.expired) {
            if (hours === '' || hours == null) {
                k.expiresAt = 'permanent';
            } else {
                const additionalTime = parseInt(hours) * 60 * 60 * 1000;
                if (k.expiresAt !== 'permanent') {
                    k.expiresAt += additionalTime;
                }
            }
        }
        return k;
    });
    saveData(KEYS_FILE, updatedKeys);
    res.redirect('/admin?access_code=buratiocadminboscotos');
});

// Route pentru adăugarea de timp unei chei
app.post('/admin/add-time', (req, res) => {
    const { key, hours } = req.body;
    const keys = loadData(KEYS_FILE);
    const updatedKeys = keys.map(k => {
        if (k.key === key && !k.expired && k.expiresAt !== 'permanent') {
            k.expiresAt += parseInt(hours) * 60 * 60 * 1000; // Add time in hours
        }
        return k;
    });
    saveData(KEYS_FILE, updatedKeys);
    res.redirect('/admin?access_code=buratiocadminboscotos');
});

const { exec } = require('child_process');

app.post('/admin/pm2', (req, res) => {
    const adminCode = req.query.access_code;

    if (adminCode !== 'buratiocadminboscotos') {
        return res.status(403).send('Unauthorized');
    }

    const { command } = req.body;
    if (!command || !command.startsWith('pm2 ')) {
        return res.status(400).send('Invalid or missing PM2 command');
    }

    exec(command, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: stderr || 'Command failed' });
        }

        res.json({ output: stdout });
    });
});

app.get('/BSMT', (req, res) => {
    const ua = req.headers['user-agent'] || '';

    if (/mozilla|chrome|safari|edge|firefox/i.test(ua)) {
        return res.redirect('https://thebasement.ink');
    }

    fs.readFile(SCRIPT_FILE, 'utf8', (err, script) => {
        if (err) {
            console.error("Error reading script:", err.message);
            return res.status(500).send('-- Internal server error');
        }

        res.setHeader('Content-Type', 'text/plain');
        res.send(script);
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
