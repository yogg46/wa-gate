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

const app = express();
const PORT = process.env.PORT || 3000;
const logFile = path.join(__dirname, 'gateway.log');
const qrFile = path.join(__dirname, 'qr.tmp');

let sock;
let qrBase64 = null;
let qrLocked = false; // Lock QR saat sedang proses scan

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'secret-wa-gateway',
  resave: false,
  saveUninitialized: true
}));

function requireLogin(req, res, next) {
  if (req.session?.loggedIn) return next();
  res.redirect('/login');
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

function writeLog(msg) {
  const timestamp = getFormattedTimestamp();
  fs.appendFileSync(logFile, `[${timestamp}] ${msg}\n`);
}

// Hapus folder auth
function clearAuthFolder() {
  const folder = path.join(__dirname, 'auth');
  fs.rm(folder, { recursive: true, force: true }, () => {});
}

// Log rotate
function rotateLogIfNeeded() {
  try {
    if (fs.existsSync(logFile)) {
      const stats = fs.statSync(logFile);
      const maxSize = 1 * 1024 * 1024;
      if (stats.size >= maxSize) {
        const backup = `gateway-${Date.now()}.log`;
        fs.renameSync(logFile, path.join(__dirname, backup));
        writeLog('📁 Log diputar karena ukuran > 1MB');
      }
    }
  } catch (e) {
    console.error('❌ Log rotate error:', e.message);
  }
}

// Start WA Socket
async function startSock() {
  rotateLogIfNeeded();

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
        qrLocked = true;
        qrBase64 = await qrcode.toDataURL(qr);
        fs.writeFileSync(qrFile, qrBase64);
        writeLog(`📸 QR diterima dan disimpan ke ${qrFile}`);

        // Auto unlock QR setelah 30 detik jika tidak berhasil koneksi
        setTimeout(() => {
          if (qrLocked) {
            qrLocked = false;
            writeLog('⏳ QR dibuka kembali karena timeout (tidak discan)');
          }
        }, 30000);

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
          startSock();
        }
      if (code !== DisconnectReason.loggedOut) {
        setTimeout(() => {
          writeLog('🔄 Mencoba koneksi ulang...');
          startSock();
        }, 3000);
        // setTimeout(() => {
        //   writeLog('🔄 clear folder auth...');
        //   clearAuthFolder();
        // }, 30000);
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
        writeLog(`📤 Webhook ke Laravel OK: ${response.status}`);
      } catch (err) {
        writeLog(`❌ Gagal webhook: ${err.message}`);
      }
    }
  });
}

startSock();

// Routes
app.get('/qr', (req, res) => {

  // const token = req.headers.authorization;
  // if (!token || token !== `Bearer ${process.env.LARAVEL_API_KEY}`) {
  //   return res.status(401).json({ status: false, message: 'Unauthorized' });
  // }
  

  if (qrBase64) {
    writeLog('✅ Mengirim QR dari memori');
    return res.send({ status: true, qr: qrBase64 });
  }

  // try {
  //   if (fs.existsSync(qrFile)) {
  //     const qr = fs.readFileSync(qrFile, 'utf8');
  //     writeLog('✅ Mengirim QR dari file cadangan');
  //     return res.send({ status: true, qr });
  //   }
  // } catch (err) {
  //   writeLog(`❌ Gagal baca file QR: ${err.message}`);
  // }

  return res.send({ status: false, qr: null, message: 'QR tidak tersedia' });
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
    writeLog(`📨 Pesan terkirim ke ${to}`);
    res.json({ status: true, message: 'Pesan berhasil dikirim' });
  } catch (err) {
    writeLog(`❌ Gagal kirim pesan ke ${to}: ${err.message}`);
    res.status(500).json({ status: false, message: 'Gagal kirim pesan', error: err.message });
  }
});

app.get('/logs', (req, res) => {
  fs.readFile(logFile, 'utf8', (err, data) => {
    if (err) return res.status(500).json({ log: `Gagal membaca log: ${err.message}` });
    const lines = data.trim().split('\n').slice(-100).join('\n');
    res.json({ log: lines });
  });
});

app.get('/login', (req, res) => {
  res.send(`
    <h2>🔐 Login WA Gateway</h2>
    <form method="POST" action="/login">
      <input name="username" placeholder="Username"><br/>
      <input name="password" type="password" placeholder="Password"><br/>
      <button type="submit">Login</button>
    </form>
  `);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.LOGIN_USERNAME && password === process.env.LOGIN_PASSWORD) {
    req.session.loggedIn = true;
    res.redirect('/dashboard');
  } else {
    res.send('<p>❌ Gagal login. <a href="/login">Coba lagi</a></p>');
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/dashboard', requireLogin, (req, res) => {
  res.send(`
    <h2>📋 Dashboard WA Gateway</h2>
    <p><a href="/qrcode">Lihat QR</a></p>
    <p><a href="/view-log">Lihat Log</a></p>
    <form method="POST" action="/logout"><button>Logout</button></form>
  `);
});

app.get('/view-log', requireLogin, (req, res) => {
  fs.readFile(logFile, 'utf8', (err, data) => {
    if (err) return res.send('Gagal membaca log.');
    const content = data.trim().split('\n').slice(-100).join('<br/>');
    res.send(`<h2>📄 Log Terakhir</h2><div style="background:#eee;padding:10px">${content}</div><p><a href="/dashboard">Kembali</a></p>`);
  });
});

app.get('/qrcode', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/', (req, res) => {
  res.send('Halo dari Node.js!');
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
