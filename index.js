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
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'secret-wa-gateway',
  resave: false,
  saveUninitialized: true
}));

function requireLogin(req, res, next) {
  if (req.session && req.session.loggedIn) {
    next();
  } else {
    res.redirect('/login');
  }
}

const PORT = process.env.PORT || 3000;
let sock;
let qrBase64 = null;
const logFile = path.join(__dirname, 'gateway.log');
const qrFile = path.join(__dirname, 'qr.tmp');

// ========== Logging ==========
function writeLog(text) {
  const timestamp = new Date().toISOString();
  fs.appendFileSync(logFile, `[${timestamp}] ${text}\n`);
}

// ========== Clear auth ==========
function clearAuthFolder() {
  const folder = path.join(__dirname, 'auth');
  fs.readdir(folder, (err, files) => {
    if (err) return;
    files.forEach((file) => {
      const filePath = path.join(folder, file);
      fs.stat(filePath, (err, stats) => {
        if (err) return;
        if (stats.isDirectory()) {
          fs.rmdir(filePath, { recursive: true }, () => {});
        } else {
          fs.unlink(filePath, () => {});
        }
      });
    });
  });
}

// ========== Log Rotate ==========
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

// ========== Start WA Socket ==========
async function startSock() {
  rotateLogIfNeeded();

  const { state, saveCreds } = await useMultiFileAuthState('auth');
  const { version } = await fetchLatestBaileysVersion();

  sock = makeWASocket({
    version,
    auth: state,
    printQRInTerminal: true,
  });

  sock.ev.on('connection.update', async (update) => {
    const { connection, qr, lastDisconnect } = update;

    if (qr) {
      const base64QR = await qrcode.toDataURL(qr);
      qrBase64 = base64QR;
      try {
        fs.writeFileSync(qrFile, base64QR);
        writeLog(`📸 QR diterima dan disimpan ke ${qrFile}`);
      } catch (err) {
        writeLog('❌ Gagal simpan QR ke file: ' + err.message);
      }
    }

    if (connection === 'open') {
      writeLog('✅ WhatsApp berhasil terhubung.');
      // qrBase64 = null; // Hapus dari memori, tapi file dibiarkan
    }

    if (connection === 'close') {
      const code = lastDisconnect?.error?.output?.statusCode;
      writeLog(`❌ Koneksi terputus: ${code}`);
      clearAuthFolder();
      if (code !== DisconnectReason.loggedOut) {
        setTimeout(() => {
          writeLog('🔄 Mencoba koneksi ulang...');
          startSock();
        }, 3000);
      }
      process.exit(1);
    }
  });

  sock.ev.on('creds.update', saveCreds);

  sock.ev.on('messages.upsert', async ({ messages }) => {
    const msg = messages[0];
    if (!msg.message || msg.key.fromMe) return;

    const from = msg.key.remoteJid;
    const body = msg.message?.conversation || msg.message?.extendedTextMessage?.text || '';
    const lowerBody = body.toLowerCase();
    const keywords = ['pinjam ruang', 'lihat ruang'];
    const matched = keywords.find(k => lowerBody.includes(k));

    if (matched) {
      writeLog(`📩 Keyword "${matched}" dari ${from}: ${body}`);

      try {
        const res = await axios.post(process.env.LARAVEL_WEBHOOK_URL, {
          from,
          body,
          timestamp: msg.messageTimestamp
        }, {
          headers: {
            'Authorization': `Bearer ${process.env.LARAVEL_API_KEY}`,
            'Content-Type': 'application/json'
          }
        });

        writeLog(`📤 Webhook ke Laravel OK: ${res.status}`);
      } catch (err) {
        writeLog(`❌ Gagal webhook: ${err.message}`);
      }
    }
  });
}

startSock();

// ========== ROUTES ==========

app.get('/qr', (req, res) => {
  writeLog('🔍 Endpoint /qr diakses');

  if (qrBase64) {
    writeLog('✅ Mengirim QR dari memori');
    return res.send({ status: true, qr: qrBase64 });
  }

  try {
    if (fs.existsSync(qrFile)) {
      const data = fs.readFileSync(qrFile, 'utf8');
      writeLog('✅ Mengirim QR dari file cadangan');
      return res.send({ status: true, qr: data });
    } else {
      writeLog(`⚠️ File QR tidak ditemukan di ${qrFile}`);
    }
  } catch (err) {
    writeLog('❌ Gagal baca file qr.tmp: ' + err.message);
    return res.status(404).send({ status: false, message: 'QR tidak tersedia' });
  }

});

app.post('/send-message', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${process.env.LARAVEL_API_KEY}`) {
    return res.status(401).send({ status: false, message: 'Unauthorized' });
  }

  const { to, message } = req.body;
  if (!to || !message) {
    return res.status(400).send({ status: false, message: 'to dan message wajib diisi' });
  }

  try {
    const jid = to.includes('@s.whatsapp.net') ? to : `${to}@s.whatsapp.net`;
    await sock.sendMessage(jid, { text: message });
    res.send({ status: true, message: 'Pesan berhasil dikirim' });
  } catch (err) {
    writeLog(`❌ Gagal kirim pesan ke ${to}: ${err.message}`);
    res.status(500).send({ status: false, message: 'Gagal kirim pesan', error: err.message });
  }
});

app.get('/logs', (req, res) => {
  fs.readFile(logFile, 'utf8', (err, data) => {
    if (err) return res.status(500).json({ log: 'Gagal membaca log: ' + err.message });
    const lines = data.trim().split('\n');
    const lastLines = lines.slice(-100).join('\n');
    res.json({ log: lastLines });
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
  if (
    username === process.env.LOGIN_USERNAME &&
    password === process.env.LOGIN_PASSWORD
  ) {
    req.session.loggedIn = true;
    res.redirect('/dashboard');
  } else {
    res.send('<p>❌ Gagal login. <a href="/login">Coba lagi</a></p>');
  }
});

app.get('/qrcode', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
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

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

function getLocalIp() {
  const interfaces = os.networkInterfaces();
  for (const iface of Object.values(interfaces)) {
    for (const config of iface) {
      if (config.family === 'IPv4' && !config.internal) {
        return config.address;
      }
    }
  }
  return 'localhost';
}

app.get('/', (req, res) => {
  res.send('Halo dari Node.js!');
});

const host = getLocalIp();
app.listen(PORT, () => {
  console.log(`🚀 Gateway aktif di http://${host}:${PORT}`);
  writeLog(`🚀 Server aktif di http://${host}:${PORT}`);
});
