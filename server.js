const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const moment = require('moment-timezone');

const app = express();
const PORT = 3000;
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Fișiere pentru stocarea datelor
const KEYS_FILE = path.join(__dirname, 'keys.json');
const BLACKLIST_FILE = path.join(__dirname, 'blacklist.json');
const NOTIFICATIONS_FILE = path.join(__dirname, 'notifications.json');

// Verifică dacă fișierele există, dacă nu, creează-le
[KEYS_FILE, BLACKLIST_FILE, NOTIFICATIONS_FILE].forEach(file => {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(file, JSON.stringify([]));
    }
});

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
function checkAccess(req, res, next) {
    const { access_code } = req.query;
    if ((req.path === '/keys' && access_code === 'vasiocburatiocsukos') ||
        (req.path === '/admin' && access_code === 'buratiocadminboscotos')) {
        return next();
    }
    res.status(401).send('Unauthorized');
}

function blacklistIp(ip, reason = 'No reason provided') {
    const blacklist = loadData(BLACKLIST_FILE);
    const now = Date.now();
    
    blacklist.push({
        type: 'ip',
        value: ip,
        reason: reason,
        expiry: 'permanent'  // Set as permanent for bypass attempts
    });
    saveData(BLACKLIST_FILE, blacklist);
}

function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    let ip = forwarded ? forwarded.split(',').shift() : req.ip;
    if (ip.startsWith('::ffff:')) {
        ip = ip.substring(7);
    }
    return ip;
}

// Funcție pentru eliminarea cheilor expirate
function removeExpiredKeys() {
    const keys = loadData(KEYS_FILE);
    const now = Date.now();
    const validKeys = keys.filter(key => key.expiresAt > now);
    saveData(KEYS_FILE, validKeys);
}

// Funcție pentru eliminarea tuturor cheilor
function removeAllKeys() {
    saveData(KEYS_FILE, []);
}

// Funcție pentru generarea unui cod unic din 6 caractere pentru blacklistId
function generateBlacklistId() {
    return Math.random().toString(36).substring(2, 8).toUpperCase();
}

// Route pentru pagina principală
app.get('/', (req, res) => {
    const ip = getClientIp(req);
    const blacklist = loadData(BLACKLIST_FILE);
    const blacklisted = blacklist.find(entry => entry.type === 'ip' && entry.value === ip && entry.expiry === 'permanent');

    if (blacklisted) {
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Access Denied</title>
                <style>
                    body {
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        background: #333;
                        color: #fff;
                        font-family: Arial, sans-serif;
                    }
                    .message { text-align: center; }
                </style>
            </head>
            <body>
                <div class="message">
                    <h1>You have been blacklisted.</h1>
                    <p>Reason: ${blacklisted.reason || 'Tried to bypass the key system'}</p>
                    <p>Duration: Indefinite</p>
                    <p>Blacklist ID: ${blacklisted.blacklistId}</p>
                </div>
            </body>
            </html>
        `);
    } else {
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Basement Hub Key System</title>
                <style>
                    body {
                        background: linear-gradient(to top, #003366, white);
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }
                    .container {
                        text-align: center;
                    }
                    h1 { color: #fff; }
                    a {
                        background-color: #0056b3;
                        color: white;
                        padding: 10px 20px;
                        text-decoration: none;
                        border-radius: 5px;
                        font-size: 16px;
                        margin: 10px;
                    }
                    a:hover { background-color: #003d80; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Welcome to Basement Hub Key System</h1>
                    <a href="/redirect-to-linkvertise">Generate a Key</a>
                    <a href="/script-info">Script Info</a>
                </div>
            </body>
            </html>
        `);
    }
});

app.get('/script-info', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Script Info</title>
            <style>
                body {
                    background: linear-gradient(to top, #003366, white);
                    font-family: Arial, sans-serif;
                    color: white;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    min-height: 100vh;
                }
                .content {
                    text-align: center;
                    max-width: 600px;
                }
                .script-box {
                    background: #333;
                    padding: 15px;
                    border-radius: 10px;
                    margin-bottom: 20px;
                }
                .script-box code {
                    display: block;
                    background: #222;
                    padding: 10px;
                    border-radius: 5px;
                    font-size: 14px;
                    color: #4caf50;
                    overflow-wrap: break-word;
                }
                .games-list button {
                    display: block;
                    background: #444;
                    color: white;
                    border: none;
                    border-radius: 5px;
                    padding: 10px;
                    margin: 5px 0;
                    cursor: pointer;
                }
                .games-list button:hover {
                    background: #0056b3;
                }
                .go-back {
                    margin-top: 20px;
                    padding: 10px 20px;
                    background: #b30000;
                    border-radius: 5px;
                    color: white;
                    text-decoration: none;
                }
                .discord-icon {
                    position: fixed;
                    bottom: 20px;
                    right: 20px;
                    width: 60px;
                    height: 60px;
                    cursor: pointer;
                }
            </style>
        </head>
        <body>
            <div class="content">
                <h1>Basement Hub Script Info</h1>
                <div class="script-box">
                    <p>Use this script in your game:</p>
                    <code>loadstring(game:HttpGet("https://raw.githubusercontent.com/Cazzanos/The-basement/main/Basement%20hub", true))()</code>
                    <button onclick="copyScript()">Copy Script</button>
                </div>
                <h2>Supported Games</h2>
                <div class="games-list">
                    <button onclick="window.location.href='https://roblox.com/life-in-prison'">Life in Prison</button>
                    <button onclick="window.location.href='https://roblox.com/sl-prison'">SL Prison</button>
                    <button onclick="window.location.href='https://roblox.com/war-tycoon'">War Tycoon</button>
                    <button onclick="window.location.href='https://roblox.com/fisch'">Fisch</button>
                    <button onclick="window.location.href='https://roblox.com/bloxfruit'">Bloxfruit</button>
                    <button onclick="window.location.href='https://roblox.com/arm-wrestling'">Arm Wrestling Simulator</button>
                    <button onclick="window.location.href='https://roblox.com/bee-swarm'">Bee Swarm Simulator</button>
                    <button onclick="window.location.href='https://roblox.com/universal'">Universal Script</button>
                </div>
                <a href="/" class="go-back">Go Back</a>
            </div>
            <img src="https://discord.com/assets/847541504914fd33810e70a0ea73177e.ico" class="discord-icon" onclick="window.location.href='https://discord.gg/VvBh5raCSW'" alt="Discord">
            <script>
                function copyScript() {
                    const script = 'loadstring(game:HttpGet("https://raw.githubusercontent.com/Cazzanos/The-basement/main/Basement%20hub", true))()';
                    navigator.clipboard.writeText(script).then(() => {
                        alert("Script copied to clipboard!");
                    });
                }
            </script>
        </body>
        </html>
    `);
});

function saveProgress(ip, checkpoint) {
    const progress = loadData('progress.json') || [];
    const existing = progress.find(entry => entry.ip === ip);
    if (existing) {
        existing.checkpoint = checkpoint;
    } else {
        progress.push({ ip, checkpoint });
    }
    saveData('progress.json', progress);
}

// Redirecționare către Linkvertise
app.get('/redirect-to-linkvertise', (req, res) => {
    const ip = getClientIp(req);

    // Salvează progresul la primul checkpoint
    saveProgress(ip, 1);

    // Redirecționează către primul Linkvertise
    res.redirect('https://link-center.net/1203734/the-basement-key1');
});

function antiBypass(req, res, next) {
    const referer = req.get('Referer');
    const ip = getClientIp(req);
    const blacklist = loadData(BLACKLIST_FILE);

    // Verifică dacă utilizatorul a venit de la Linkvertise
    if (referer && referer.includes("linkvertise.com")) {
        return next(); // Permite accesul
    }

    // Adaugă utilizatorul pe blacklist dacă nu există deja
    let blacklisted = blacklist.find(entry => entry.type === 'ip' && entry.value === ip);
    if (!blacklisted) {
        blacklisted = {
            type: 'ip',
            value: ip,
            reason: 'Tried to bypass the key system',
            expiry: 'permanent',
            blacklistId: `BL-${Math.random().toString(36).substr(2, 8).toUpperCase()}`
        };
        blacklist.push(blacklisted);
        saveData(BLACKLIST_FILE, blacklist);
    }

    // Mesaj anti-bypass
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Nice Try Bozo</title>
            <style>
                body {
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    background: #333;
                    color: #fff;
                    font-family: Arial, sans-serif;
                    text-align: center;
                }
                h1 { font-size: 3rem; margin: 0; }
                p { font-size: 1.2rem; margin-top: 10px; }
            </style>
        </head>
        <body>
            <div>
                <h1>Nice try, bozo!</h1>
                <p>Your IP has been blacklisted for attempting to bypass the key system.</p>
                <p>Contact a moderator from Basement Hub.</p>
            </div>
        </body>
        </html>
    `);
}

// Checkpoint 2: Redirecționare către al doilea Linkvertise
app.get('/checkpoint2', antiBypass, (req, res) => {
    const ip = getClientIp(req);
    const progress = loadData('progress.json') || [];
    const userProgress = progress.find(entry => entry.ip === ip);

    // Verifică progresul
    if (userProgress && userProgress.checkpoint >= 2) {
        res.redirect('/key-generated');
        return;
    }

    // Salvează progresul pentru checkpoint2
    saveProgress(ip, 2);

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Basement Hub Key System | Checkpoint 2</title>
            <style>
                body {
                    background: linear-gradient(to top, #003366, white);
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                h1 {
                    color: white;
                }
                a {
                    background-color: #0056b3;
                    color: white;
                    padding: 10px 20px;
                    text-decoration: none;
                    border-radius: 5px;
                    font-size: 16px;
                }
                a:hover {
                    background-color: #003d80;
                }
            </style>
        </head>
        <body>
            <div>
                <h1>Basement Hub Key System | Checkpoint 2</h1>
                <a href="https://link-target.net/1203734/key">Complete Checkpoint 2</a>
            </div>
        </body>
        </html>
    `);
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

    // Serve the HTML file for bypass attempt
    res.sendFile(path.join(__dirname, 'public', 'bypassbozo.html'));
});

// După finalizarea Checkpoint 2, redirecționează către pagina key-generated
app.get('/key-generated', antiBypass, (req, res) => {
    const ip = getClientIp(req);
    const keys = loadData(KEYS_FILE);
    let existingKey = keys.find(key => key.ip === ip && !key.expired);

    if (!existingKey) {
        existingKey = createKey(ip); // Creează o cheie nouă dacă nu există
    }

    // Salvează progresul pentru key-generated
    saveProgress(ip, 3);

    const timeLeft = existingKey.expiresAt - Date.now();
    const hours = Math.floor((timeLeft % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Your Generated Key</title>
            <style>
                body {
                    background: linear-gradient(to bottom, #003366, white);
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                h1 {
                    color: #fff;
                }
                p {
                    color: #333;
                }
                a {
                    background-color: #0056b3;
                    color: white;
                    padding: 10px 20px;
                    text-decoration: none;
                    border-radius: 5px;
                    font-size: 16px;
                }
                a:hover {
                    background-color: #003d80;
                }
                .timer {
                    font-size: 18px;
                    color: #ff0000;
                }
            </style>
        </head>
        <body>
            <div>
                <h1>Your Generated Key</h1>
                <p>Your new key: <strong>${existingKey.key}</strong></p>
                <p>It will expire in: <strong><span id="timer">${hours}h ${minutes}m ${seconds}s</span></strong></p>
                <a href="/reset-key">Reset Key</a>
            </div>
            <script>
                var countDownDate = new Date().getTime() + ${timeLeft};
                var x = setInterval(function() {
                    var now = new Date().getTime();
                    var distance = countDownDate - now;
                    var hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                    var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                    var seconds = Math.floor((distance % (1000 * 60)) / 1000);
                    document.getElementById("timer").innerHTML = hours + "h " + minutes + "m " + seconds + "s ";
                    if (distance < 0) {
                        clearInterval(x);
                        document.getElementById("timer").innerHTML = "EXPIRED";
                        setTimeout(function() {
                            location.reload();
                        }, 1000);
                    }
                }, 1000);
            </script>
        </body>
        </html>
    `);
});

// Route pentru resetarea unei chei
app.get('/reset-key', (req, res) => {
    const ip = getClientIp(req);
    let keys = loadData(KEYS_FILE);
    keys = keys.filter(key => key.ip !== ip);  // Șterge orice cheie asociată cu acest IP
    saveData(KEYS_FILE, keys);

    res.redirect('/');
});

// Route pentru verificarea unei chei
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
    saveData(BLACKLIST_FILE, []); // Golirea fișierului de blacklist
    res.redirect('/admin?access_code=buratiocadminboscotos'); // Redirect către pagina de admin
});

app.post('/admin/create-permanent-key', (req, res) => {
    const { key } = req.body;
    const keys = loadData(KEYS_FILE);

    const newKey = {
        key: key,
        ip: 'admin',
        maxUsers: 2, // Ajustează acest număr dacă este nevoie
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

// Codul complet pentru pagina de admin cu toate cerințele tale

// Rota admin cu toate cerințele adăugate
app.get('/admin', checkAccess, (req, res) => {
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

// Route pentru adăugarea pe blacklist
// Generare ID unic pentru blacklist (6 caractere alfanumerice)
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

// Route pentru ștergerea de pe blacklist
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

// Pornire server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
