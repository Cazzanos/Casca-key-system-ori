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

const KEYS_FILE = path.join(__dirname, 'keys.json');
const BLACKLIST_FILE = path.join(__dirname, 'blacklist.json');
const NOTIFICATIONS_FILE = path.join(__dirname, 'notifications.json');
const PROGRESS_FILE = path.join(__dirname, 'progress.json');
if (!fs.existsSync(PROGRESS_FILE)) {
    fs.writeFileSync(PROGRESS_FILE, JSON.stringify([]));
}

// Verifică dacă fișierele există, dacă nu, creează-le
[KEYS_FILE, BLACKLIST_FILE, NOTIFICATIONS_FILE].forEach(file => {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(file, JSON.stringify([]));
    }
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
    }
    
    userProgress.lastAccess = Date.now();
    
    saveData(PROGRESS_FILE, progressData);
}

function cleanOldProgress() {
    const progress = loadData(PROGRESS_FILE);
    const HOUR = 3600000;
    const cleaned = progress.filter(entry => 
        Date.now() - entry.lastAccess < (24 * HOUR) // Keep for 24h
    );
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
function checkAccess(req, res, next) {
    const { access_code } = req.query;
    if ((req.path === '/keys' && access_code === 'vasiocburatiocsukos') ||
        (req.path === '/admin' && access_code === 'buratiocadminboscotos')) {
        return next();
    }
    res.status(401).send('Unauthorized');
}

function blacklistIp(ip, reason) {
    let blacklist = loadData(BLACKLIST_FILE);
    const existingEntry = blacklist.find(entry => 
        entry.type === 'ip' && entry.value === ip
    );

    if (existingEntry) {
        existingEntry.reason = reason || existingEntry.reason;
        existingEntry.expiry = 'permanent';
        existingEntry.blacklistId = existingEntry.blacklistId || generateBlacklistId();
    } else {
        blacklist.push({
            type: 'ip',
            value: ip,
            reason: reason || 'Bypass attempt',
            blacklistId: generateBlacklistId(),
            expiry: 'permanent'
        });
    }
    saveData(BLACKLIST_FILE, blacklist);
}

function getClientIp(req) {
    let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    if (ip.includes(',')) {
        ip = ip.split(',')[0];
    }

    if (ip.startsWith('::ffff:')) {
        ip = ip.substring(7); 
    }

    return ip.trim();
}

// Funcție pentru eliminarea cheilor expirate
function removeExpiredKeys() {
    const keys = loadData(KEYS_FILE);
    const now = Date.now();
    const validKeys = keys.filter(key => key.expiresAt > now);

    keys.forEach(key => {
        if (key.expiresAt <= now) {
            resetProgress(key.ip);
        }
    });

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
    const ip = getClientIp(req); // Obține IP-ul utilizatorului
    const blacklist = loadData(BLACKLIST_FILE); // Încarcă lista de blacklist
    const blacklisted = blacklist.find(entry => entry.type === 'ip' && entry.value === ip && entry.expiry === 'permanent');

    if (blacklisted) {
        // Dacă utilizatorul este pe blacklist
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
                    <p>Blacklist ID: ${blacklisted.blacklistId || 'N/A'}</p>
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
                <div>
                    <h1>Welcome to Basement Hub Key System</h1>
                    <a href="/redirect-to-linkvertise">Generate a Key</a>
                    <a href="/key-info">Key Info</a>
                    <a href="/script-info">Script Info</a> <!-- Butonul "Script Info" -->
                </div>
            </body>
            </html>
        `);
    }
});

// 🟢 FIXED: Removed duplicate script tag
app.get('/key-info', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Key Info</title>
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
                    max-width: 600px;
                }
                input[type="text"] {
                    width: 80%;
                    padding: 10px;
                    margin: 10px 0;
                    border: 1px solid #ccc;
                    border-radius: 5px;
                }
                button {
                    background-color: #0056b3;
                    color: white;
                    padding: 10px 20px;
                    border: none;
                    border-radius: 5px;
                    font-size: 16px;
                    margin: 5px;
                    cursor: pointer;
                }
                button:hover {
                    background-color: #003d80;
                }
                .error {
                    color: red;
                    font-size: 14px;
                    margin-top: 10px;
                }
                .success {
                    color: green;
                    font-size: 14px;
                    margin-top: 10px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Key Info</h1>
                <input type="text" id="keyInput" placeholder="Enter your key here">
                <button onclick="searchKey()">Search</button>
                <button onclick="findMyKey()">Find My Key IP</button>
                <p id="message" class="error"></p>
            </div>
            <script>
                function searchKey() {
                    const key = document.getElementById("keyInput").value;
                    if (!key) {
                        document.getElementById("message").innerText = "Please enter a key!";
                        return;
                    }
                    fetch('/search-key?key=' + encodeURIComponent(key), {
                           method: 'GET',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ key })
                    })
                    .then(res => res.json())
                    .then(data => {
                        if (data.success) {
                            window.location.href = '/key-details?key=' + key;
                        } else {
                            document.getElementById("message").innerText = data.message;
                        }
                    })
                    .catch(err => {
                        document.getElementById("message").innerText = "An error occurred while searching.";
                    });
                }

                function findMyKey() {
                    fetch('/find-my-key', { method: 'GET' })
                        .then(res => res.json())
                        .then(data => {
                            if (data.success) {
                                window.location.href = '/key-details?key=' + data.key;
                            } else {
                                document.getElementById("message").innerText = data.message;
                            }
                        })
                        .catch(err => {
                            document.getElementById("message").innerText = "An error occurred while finding your key.";
                        });
                }
            </script>
        </body>
        </html>
    `);
});

app.get('/search-key', (req, res) => {
    const { key } = req.body;
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

app.get('/blacklist', (req, res) => {
    const ip = getClientIp(req);
    const blacklist = loadData(BLACKLIST_FILE);
    const blacklisted = blacklist.find(entry => entry.type === 'ip' && entry.value === ip);

    if (!blacklisted) {
        return res.redirect('/');
    }

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Access Denied</title>
            <style>
                body { display: flex; justify-content: center; align-items: center; height: 100vh; background: #333; color: #fff; font-family: Arial, sans-serif; }
                .message { text-align: center; }
            </style>
        </head>
        <body>
            <div class="message">
                <h1>You have been blacklisted.</h1>
                <p>Reason: ${blacklisted.reason || 'Tried to bypass the key system'}</p>
                <p>Blacklist ID: ${blacklisted.blacklistId}</p>
            </div>
        </body>
        </html>
    `);
});

app.get('/key-details', (req, res) => {
    const { key } = req.query;
    const keys = loadData(KEYS_FILE);
    const foundKey = keys.find(entry => entry.key === key);

    if (!foundKey) {
        return res.status(404).send(`
            <h1>Key Not Found</h1>
            <p>The provided key does not exist or has expired.</p>
        `);
    }

    const timeLeft = foundKey.expiresAt - Date.now();
    const hours = Math.floor((timeLeft % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <title>Key Details</title>
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
                .container {
                    text-align: center;
                    color: white;
                }
                .timer {
                    font-size: 1.5rem;
                    color: red;
                }
                .go-back {
                    background-color: #d9534f;
                    color: white;
                    padding: 10px 20px;
                    text-decoration: none;
                    border-radius: 5px;
                    font-size: 1.2rem;
                    display: inline-block;
                    margin-top: 15px;
                }
                .go-back:hover {
                    background-color: #c9302c;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Key Details</h1>
                <p><strong>Key:</strong> ${foundKey.key}</p>
                <p><strong>Expires In:</strong> <span id="timer">${hours}h ${minutes}m ${seconds}s</span></p>
                <p><strong>Used By:</strong> ${foundKey.usedBy.length > 0 ? foundKey.usedBy.join(", ") : "No users currently."}</p>
                <a href="/key-info" class="go-back">Go Back</a>
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
                    }
                }, 1000);
            </script>
        </body>
        </html>
    `);
});

app.post('/unbind-key', (req, res) => {
    const { key } = req.body;
    const keys = loadData(KEYS_FILE);

    const foundKey = keys.find(k => k.key === key);
    if (!foundKey) {
        return res.json({ success: false, message: 'Key not found.' });
    }

    foundKey.users = []; // Curăță utilizatorii
    foundKey.inUse = false; // Resetează starea de utilizare
    saveData(KEYS_FILE, keys);

    res.json({ success: true, message: 'All users unbound from this key.' });
});

app.post('/addtime', (req, res) => {
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

app.post('/unbind', (req, res) => {
    const { key } = req.body;
    const keys = loadData(KEYS_FILE);

    const foundKey = keys.find(k => k.key === key);
    if (!foundKey) {
        return res.status(404).json({ error: 'Key not found.' });
    }

    foundKey.usedBy = [];
    foundKey.inUse = false;
    saveData(KEYS_FILE, keys);
    res.json({ success: true, message: 'Unbound all users from the key.' });
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
                    <button onclick="window.location.href='https://www.roblox.com/games/8689257920/Life-in-Prison'">Life in Prison</button>
                    <button onclick="window.location.href='https://www.roblox.com/games/16792181861/SL-PRISON'">SL Prison</button>
                    <button onclick="window.location.href='https://www.roblox.com/games/4639625707/Nighthawk-War-Tycoon'">War Tycoon</button>
                    <button onclick="window.location.href='https://www.roblox.com/games/16732694052/Fisch-ATLANTIS'">Fisch</button>
                    <button onclick="window.location.href='https://www.roblox.com/games/2753915549/Blox-Fruits'">Bloxfruit</button>
                    <button onclick="window.location.href='https://www.roblox.com/games/13127800756/Arm-Wrestle-Simulator?gameSearchSessionInfo=4588946f-1ef3-4135-a824-851a89d15af8&isAd=false&nativeAdData=&numberOfLoadedTiles=40&page=searchPage&placeId=13127800756&position=0&universeId=4582358979'">Arm Wrestling Simulator</button>
                    <button onclick="window.location.href='https://www.roblox.com/games/1537690962/Bee-Swarm-Simulator'">Bee Swarm Simulator</button>
                    <button onclick="window.location.href='https://www.roblox.com/home'">Universal Script</button>
                </div>
                <a href="/" class="go-back">Go Back</a>
            </div>
            <img src="https://cdn.discordapp.com/embed/avatars/0.png" class="discord-icon" onclick="window.location.href='https://discord.gg/VvBh5raCSW'" alt="Discord">
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

app.get('/redirect-to-linkvertise', (req, res) => {
    const ip = getClientIp(req);
    saveProgress(ip, 'redirect-to-linkvertise');
    res.redirect('https://link-center.net/1203734/the-basement-key1');
});

function antiBypass(req, res, next) {
    const ip = getClientIp(req);
    const progress = loadData(PROGRESS_FILE);
    const userProgress = progress.find(entry => entry.ip === ip);
    
    const requiredCheckpoints = {
        '/checkpoint2': ['redirect-to-linkvertise'],
        '/key-generated': ['redirect-to-linkvertise', 'checkpoint2']
    };

    // Skip if no checkpoints required for this path
    if (!requiredCheckpoints[req.path]) return next();

    const hasAllCheckpoints = requiredCheckpoints[req.path].every(cp => 
        userProgress?.checkpoints?.includes(cp)
    );

    // Allow if checkpoints are satisfied
    if (hasAllCheckpoints) return next();

    // Check if coming from Linkvertise
    const referer = req.get('Referer');
    if (referer && (referer.includes("linkvertise.com") || referer.includes("link-center.net"))) {
        // Automatically add the first checkpoint if missing
        if (!userProgress) {
            saveProgress(ip, 'redirect-to-linkvertise');
        } else if (!userProgress.checkpoints.includes('redirect-to-linkvertise')) {
            saveProgress(ip, 'redirect-to-linkvertise');
        }
        return next();
    }

    // Blacklist if checkpoints are missing and referrer is invalid
    blacklistIp(ip, 'Bypass attempt');
    return res.redirect('/blacklist');
}

app.get('/checkpoint2', antiBypass, (req, res) => {
    const ip = getClientIp(req);
    const progress = loadData(PROGRESS_FILE);
    const userProgress = progress.find(entry => entry.ip === ip);

    if (!userProgress || 
        !userProgress.checkpoints?.includes('redirect-to-linkvertise')
    ) {
        blacklistIp(ip, 'Bypassed checkpoint1');
        return res.redirect('/blacklist');
    }

    saveProgress(ip, 'checkpoint2');

    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Checkpoint 2</title>
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
                    font-size: 2.5rem;
                }
                a {
                    background-color: #0056b3;
                    color: white;
                    padding: 10px 20px;
                    text-decoration: none;
                    border-radius: 5px;
                    font-size: 1.2rem;
                }
                a:hover {
                    background-color: #003d80;
                }
            </style>
        </head>
        <body>
            <div>
                <h1>Basement Hub Key System | Checkpoint 2</h1>
                <a href="https://link-target.net/1203734/key" id="linkvertise">Complete Checkpoint 2</a>
            </div>
            <script>
                document.getElementById("linkvertise").addEventListener("click", function() {
                    setTimeout(function() {
                        window.location.href = "/key-generated";
                    }, 2000);
                });
            </script>
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

    res.sendFile(path.join(__dirname, 'public', 'bypassbozo.html'));
});

app.get('/key-generated', antiBypass, (req, res) => {
const ip = getClientIp(req);
    let keys = loadData(KEYS_FILE);

    let existingKey = keys.find(key => key.ip === ip && !key.expired);

    // 🛠 Fix: Check if a valid key exists
    if (!existingKey) {
        return res.redirect('/');
    }

    const timeLeft = existingKey.expiresAt - Date.now();

    // 🛠 Fix: Expired key should not regenerate
    if (timeLeft <= 0) {
        existingKey.expired = true;
        saveData(KEYS_FILE, keys);
        resetProgress(ip); // Also reset progress
        return res.redirect('/');
    }

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <title>Your Generated Key</title>
            <style>
                body { background: linear-gradient(to bottom, #003366, white); font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                h1 { color: #fff; font-size: 2.5rem; }
                p { color: #333; font-size: 1.2rem; }
                a { background-color: #0056b3; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 1.2rem; }
                a:hover { background-color: #003d80; }
                .timer { font-size: 1.5rem; color: #ff0000; margin-top: 15px; }
                .container { text-align: center; }
                .reset-btn { margin-top: 20px; background-color: #d9534f; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 1.2rem; }
                .reset-btn:hover { background-color: #c9302c; }
                .go-home { margin-top: 20px; background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 1.2rem; }
                .go-home:hover { background-color: #45a049; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Your Generated Key</h1>
                <p>Your new key: <strong>${existingKey.key}</strong></p>
                <p>It will expire in: <strong><span id="timer">${Math.floor(timeLeft / 3600000)}h ${(timeLeft % 3600000) / 60000}m</span></strong></p>
                <a href="/reset-key" class="reset-btn">Reset Key</a>
                <a href="/" class="go-home">Go Home</a>
            </div>
            <script>
                var countDownDate = new Date().getTime() + ${timeLeft};
                var x = setInterval(function() {
                    var now = new Date().getTime();
                    var distance = countDownDate - now;

                    var hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                    var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));

                    document.getElementById("timer").innerHTML = hours + "h " + minutes + "m";

                    if (distance < 0) {
                        clearInterval(x);
                        document.getElementById("timer").innerHTML = "EXPIRED";
                        setTimeout(function() {
                            window.location.href = "/";
                        }, 1000);
                    }
                }, 1000);
            </script>
        </body>
        </html>
    `);
});

app.post('/delete-key', (req, res) => {
    const { key } = req.body;
    const keys = loadData(KEYS_FILE);

    const index = keys.findIndex(k => k.key === key);
    if (index === -1) {
        return res.status(404).json({ success: false, message: 'Key not found.' });
    }

    keys.splice(index, 1);
    saveData(KEYS_FILE, keys);

    res.json({ success: true, message: `Key "${key}" has been deleted.` });
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

app.post('/reset-all', (req, res) => {
    const adminCode = req.query.admin_code;
    
    // Security check
    if (adminCode !== 'buratiocadminboscotos') {
        return res.status(401).json({ error: "Unauthorized" });
    }

    // Reset JSON files
    saveData(KEYS_FILE, []);
    saveData(BLACKLIST_FILE, []);
    saveData(PROGRESS_FILE, []);

    res.json({ success: true, message: "All data has been reset." });
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

app.post('/admin/clear-blacklist', (req, res) => {
    saveData(BLACKLIST_FILE, []);
    res.redirect('/admin?access_code=buratiocadminboscotos');
});

app.post('/create-key', (req, res) => {
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

// Pornire server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
