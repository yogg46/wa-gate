// ========== SERVER.JS ==========
require('dotenv').config();

const {
  default: makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  DisconnectReason
} = require('@whiskeysockets/baileys');

const express = require('express');
const cors = require('cors');
const qrcode = require('qrcode');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const os = require('os');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;
const logsDir = path.join(__dirname, 'logs');
const qrFile = path.join(__dirname, 'qr.tmp');

// Buat folder logs jika belum ada
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

let sock;
let qrBase64 = null;
let qrLocked = false;
let qrLockTime = null;

function lockQR() {
  qrLocked = true;
  qrLockTime = Date.now();
}

function unlockQR(force = false) {
  if (force || Date.now() - qrLockTime > 30000) {
    qrLocked = false;
    qrLockTime = null;
    writeLog('⏳ QR unlocked.');
  }
}

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret-wa-gateway',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 24 jam
}));

function requireLogin(req, res, next) {
  if (req.session?.loggedIn) return next();
  res.redirect('/login');
}

function requireAuth(req, res, next) {
  const token = req.headers.authorization;
  if (!token || token !== `Bearer ${process.env.LARAVEL_API_KEY}`) {
    return res.status(401).json({ status: false, message: 'Unauthorized' });
  }
  next();
}

function getFormattedTimestamp() {
  const now = new Date();
  const yyyy = now.getFullYear();
  const MM = String(now.getMonth() + 1).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  const HH = String(now.getHours()).padStart(2, '0');
  const mm = String(now.getMinutes()).padStart(2, '0');
  const ss = String(now.getSeconds()).padStart(2, '0');
  return `${yyyy}-${MM}-${dd} ${HH}:${mm}:${ss}`;
}

function getLogFileName() {
  const now = new Date();
  const yyyy = now.getFullYear();
  const MM = String(now.getMonth() + 1).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  return path.join(logsDir, `gateway-${yyyy}-${MM}-${dd}.log`);
}

function writeLog(msg) {
  const timestamp = getFormattedTimestamp();
  const logFile = getLogFileName();
  fs.appendFileSync(logFile, `[${timestamp}] ${msg}\n`);
}

// Hapus log lebih dari 14 hari
function cleanupOldLogs() {
  try {
    const files = fs.readdirSync(logsDir)
      .filter(file => file.startsWith('gateway-') && file.endsWith('.log'))
      .map(file => {
        const fullPath = path.join(logsDir, file);
        return {
          name: file,
          path: fullPath,
          time: fs.statSync(fullPath).mtime.getTime()
        };
      });

    const now = Date.now();
    const fourteenDays = 14 * 24 * 60 * 60 * 1000;

    files.forEach(file => {
      if (now - file.time > fourteenDays) {
        fs.unlinkSync(file.path);
        writeLog(`🗑️ Log lama dihapus: ${file.name}`);
      }
    });
  } catch (e) {
    writeLog(`❌ Cleanup log error: ${e.message}`);
  }
}

// Jalankan cleanup setiap hari jam 00:00
function scheduleLogCleanup() {
  const now = new Date();
  const night = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate() + 1,
    0, 0, 0
  );
  const msToMidnight = night.getTime() - now.getTime();

  setTimeout(() => {
    cleanupOldLogs();
    scheduleLogCleanup(); // Schedule next cleanup
  }, msToMidnight);
}

scheduleLogCleanup();
cleanupOldLogs(); // Run on startup

// Hapus folder auth
function clearAuthFolder() {
  const folder = path.join(__dirname, 'auth');
  fs.rm(folder, { recursive: true, force: true }, () => {});
}

// Start WA Socket
async function startSock() {
  const { state, saveCreds } = await useMultiFileAuthState('auth');
  const { version } = await fetchLatestBaileysVersion();

  sock = makeWASocket({
    version,
    auth: state,
    printQRInTerminal: true
  });

  sock.ev.on('connection.update', async (update) => {
    const { connection, qr, lastDisconnect } = update;

    if (qr && !qrLocked) {
      try {
        lockQR();
        qrBase64 = await qrcode.toDataURL(qr);
        fs.writeFileSync(qrFile, qrBase64);
        writeLog(`📸 QR diterima dan disimpan`);
        setTimeout(unlockQR, 30000);
      } catch (err) {
        writeLog(`❌ Gagal simpan QR: ${err.message}`);
      }
    }

    if (connection === 'open') {
      writeLog('✅ WhatsApp berhasil terhubung.');
      setTimeout(() => {
        qrBase64 = null;
        qrLocked = false;
        if (fs.existsSync(qrFile)) fs.unlinkSync(qrFile);
        writeLog('🧹 QR dihapus karena koneksi sukses');
      }, 5000);
    }

    if (connection === 'close') {
      const code = lastDisconnect?.error?.output?.statusCode;
      writeLog(`❌ Koneksi terputus: ${code}`);
      if (code === 401) {
        writeLog('🔐 401 Unauthorized - Membersihkan auth folder');
        clearAuthFolder();
        setTimeout(startSock, 2000);
      }
      if (code !== DisconnectReason.loggedOut) {
        setTimeout(() => {
          writeLog('🔄 Mencoba koneksi ulang...');
          startSock();
        }, 3000);
      }
    }
  });

  sock.ev.on('creds.update', saveCreds);

  sock.ev.on('messages.upsert', async ({ messages }) => {
    const msg = messages[0];
    if (!msg.message || msg.key.fromMe) return;

    const from = msg.key.remoteJid;
    const body = msg.message?.conversation || msg.message?.extendedTextMessage?.text || '';
    const lower = body.toLowerCase();

    const matched = ['pinjam ruang', 'lihat ruang'].find(k => lower.includes(k));
    if (matched) {
      writeLog(`📩 Keyword "${matched}" dari ${from}: ${body}`);

      try {
        const response = await axios.post(process.env.LARAVEL_WEBHOOK_URL, {
          from, body, timestamp: msg.messageTimestamp
        }, {
          headers: {
            Authorization: `Bearer ${process.env.LARAVEL_API_KEY}`,
            'Content-Type': 'application/json'
          }
        });
        writeLog(`📤 Webhook OK (${response.status}): ${JSON.stringify(response.data)}`);
      } catch (err) {
        writeLog(`❌ Gagal webhook: ${err.message}`);
      }
    }
  });
}

startSock();

// ========== ROUTES ==========

app.get('/login', (req, res) => {
  if (req.session?.loggedIn) {
    return res.redirect('/dashboard');
  }
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.LOGIN_USERNAME && password === process.env.LOGIN_PASSWORD) {
    req.session.loggedIn = true;
    res.redirect('/dashboard');
  } else {
    res.redirect('/login?error=1');
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/dashboard', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/broadcast', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'pesan.html'));
});

app.get('/qr', requireAuth, (req, res) => {
  if (qrBase64) {
    writeLog('✅ Mengirim QR dari memori');
    return res.send({ status: true, qr: qrBase64 });
  }
  return res.send({ status: false, qr: null, message: 'QR tidak tersedia' });
});

app.get('/logs', requireAuth, (req, res) => {
  const logFile = getLogFileName();
  fs.readFile(logFile, 'utf8', (err, data) => {
    if (err) {
      return res.json({ log: '', message: 'Belum ada log hari ini' });
    }
    const lines = data.trim().split('\n').slice(-200).join('\n');
    res.json({ log: lines });
  });
});

app.get('/logs/list', requireAuth, (req, res) => {
  try {
    const files = fs.readdirSync(logsDir)
      .filter(file => file.startsWith('gateway-') && file.endsWith('.log'))
      .map(file => {
        const fullPath = path.join(logsDir, file);
        return {
          name: file,
          date: file.replace('gateway-', '').replace('.log', ''),
          size: fs.statSync(fullPath).size,
          modified: fs.statSync(fullPath).mtime
        };
      })
      .sort((a, b) => b.modified - a.modified);
    
    res.json({ status: true, logs: files });
  } catch (err) {
    res.status(500).json({ status: false, message: err.message });
  }
});

app.get('/logs/download/:date', requireAuth, (req, res) => {
  const date = req.params.date;
  const logFile = path.join(logsDir, `gateway-${date}.log`);
  
  if (!fs.existsSync(logFile)) {
    return res.status(404).json({ status: false, message: 'Log tidak ditemukan' });
  }
  
  res.download(logFile);
});

app.post('/send-message', async (req, res) => {
  const token = req.headers.authorization;
  if (!token || token !== `Bearer ${process.env.LARAVEL_API_KEY}`) {
    return res.status(401).json({ status: false, message: 'Unauthorized' });
  }

  const { to, message } = req.body;
  if (!to || !message) {
    return res.status(400).json({ status: false, message: 'to dan message wajib diisi' });
  }

  try {
    const jid = to.includes('@s.whatsapp.net') ? to : `${to}@s.whatsapp.net`;
    await sock.sendMessage(jid, { text: message });
    const shortMessage = message.replace(/\n/g, ' ').slice(0, 100);
    writeLog(`📨 Pesan terkirim ke ${to}`);
    writeLog(`📨 Ringkasan: ${shortMessage}${message.length > 100 ? '...' : ''}`);
    res.json({ status: true, message: 'Pesan berhasil dikirim' });
  } catch (err) {
    writeLog(`❌ Gagal kirim pesan ke ${to}: ${err.message}`);
    res.status(500).json({ status: false, message: 'Gagal kirim pesan', error: err.message });
  }
});

app.post('/restart', requireAuth, async (req, res) => {
  try {
    writeLog('🔄 Restart Gateway diminta via dashboard');
    res.json({ status: true, message: 'Gateway sedang direstart via PM2...' });
    
    setTimeout(() => {
      const appName = process.env.PM2_APP_NAME || 'wa-gateway';
      exec(`pm2 restart ${appName}`, (error, stdout, stderr) => {
        if (error) {
          writeLog(`❌ PM2 restart error: ${error.message}`);
          return;
        }
        if (stderr) writeLog(`⚠️ PM2 restart stderr: ${stderr}`);
        writeLog(`✅ PM2 restart output: ${stdout}`);
      });
    }, 500);
  } catch (err) {
    writeLog(`❌ Gagal restart: ${err.message}`);
    res.status(500).json({ status: false, message: 'Gagal restart', error: err.message });
  }
});

app.get('/api/config', (req, res) => {
  res.json({
    apiUrl: `http://${getLocalIp()}:${PORT}`,
    apiKey: process.env.LARAVEL_API_KEY || ''
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: sock?.ws?.readyState === 1 ? 'connected' : 'disconnected',
    memory: process.memoryUsage(),
    uptime: process.uptime()
  });
});

app.get('/', (req, res) => {
  res.send('WhatsApp Gateway is running. Please <a href="/login">login</a> to access dashboard.');
  // tunggu 3 detik lalu redirect ke /login
  setTimeout(() => {
    res.redirect('/login');
  }, 2000);
});

function getLocalIp() {
  const interfaces = os.networkInterfaces();
  for (const iface of Object.values(interfaces)) {
    for (const config of iface) {
      if (config.family === 'IPv4' && !config.internal) return config.address;
    }
  }
  return 'localhost';
}

const host = getLocalIp();
app.listen(PORT, () => {
  console.log(`🚀 Gateway aktif di http://${host}:${PORT}`);
  writeLog(`🚀 Server aktif di http://${host}:${PORT}`);
});