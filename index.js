// ========== SERVER.JS - ENHANCED VERSION ==========
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
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const session = require('express-session');
const os = require('os');
const { exec } = require('child_process');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// ========== CONFIGURATION & VALIDATION ==========
const CONFIG = {
  PORT: process.env.PORT || 3000,
  SESSION_SECRET: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  LOGIN_USERNAME: process.env.LOGIN_USERNAME,
  LOGIN_PASSWORD: process.env.LOGIN_PASSWORD,
  LARAVEL_API_KEY: process.env.LARAVEL_API_KEY,
  LARAVEL_WEBHOOK_URL: process.env.LARAVEL_WEBHOOK_URL,
  PM2_APP_NAME: process.env.PM2_APP_NAME || 'wa-gateway',
  MAX_LOGIN_ATTEMPTS: parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5,
  LOGIN_COOLDOWN_MS: parseInt(process.env.LOGIN_COOLDOWN_MS) || 15 * 60 * 1000,
  MESSAGE_RETRY_ATTEMPTS: parseInt(process.env.MESSAGE_RETRY_ATTEMPTS) || 3,
  MESSAGE_RETRY_DELAY_MS: parseInt(process.env.MESSAGE_RETRY_DELAY_MS) || 2000,
  LOG_RETENTION_DAYS: parseInt(process.env.LOG_RETENTION_DAYS) || 14,
  MAX_LOG_SIZE_MB: parseInt(process.env.MAX_LOG_SIZE_MB) || 10
};

// Validasi environment variables yang wajib
function validateEnv() {
  const required = ['LOGIN_USERNAME', 'LOGIN_PASSWORD', 'LARAVEL_API_KEY', 'LARAVEL_WEBHOOK_URL'];
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    console.error(`❌ Environment variable wajib tidak ditemukan: ${missing.join(', ')}`);
    process.exit(1);
  }
  
  if (CONFIG.SESSION_SECRET === process.env.SESSION_SECRET && process.env.SESSION_SECRET?.length < 32) {
    console.warn('⚠️ SESSION_SECRET terlalu pendek. Gunakan minimal 32 karakter!');
  }
}

validateEnv();

// ========== LOGGING SYSTEM WITH LEVELS ==========
const LOG_LEVELS = {
  ERROR: '❌',
  WARN: '⚠️',
  INFO: 'ℹ️',
  SUCCESS: '✅',
  DEBUG: '🔍',
  SECURITY: '🔐',
  NETWORK: '🌐',
  MESSAGE: '📨',
  QR: '📸',
  CLEANUP: '🗑️',
  RESTART: '🔄'
};

class Logger {
  constructor(logsDir) {
    this.logsDir = logsDir;
    this.currentLogSize = 0;
    this.initLogsDir();
  }

  async initLogsDir() {
    try {
      await fs.mkdir(this.logsDir, { recursive: true });
    } catch (err) {
      console.error('❌ Gagal membuat direktori logs:', err.message);
    }
  }

  getFormattedTimestamp() {
    const now = new Date();
    return now.toISOString().replace('T', ' ').substring(0, 19);
  }

  getLogFileName() {
    const now = new Date();
    const yyyy = now.getFullYear();
    const MM = String(now.getMonth() + 1).padStart(2, '0');
    const dd = String(now.getDate()).padStart(2, '0');
    return path.join(this.logsDir, `gateway-${yyyy}-${MM}-${dd}.log`);
  }

  async log(level, message, metadata = {}) {
    const icon = LOG_LEVELS[level] || 'ℹ️';
    const timestamp = this.getFormattedTimestamp();
    const logFile = this.getLogFileName();
    
    const metaStr = Object.keys(metadata).length > 0 
      ? ` | ${JSON.stringify(metadata)}` 
      : '';
    
    const logEntry = `[${timestamp}] [${level}] ${icon} ${message}${metaStr}\n`;
    
    // Console output
    console.log(logEntry.trim());
    
    // File output (async)
    try {
      await fs.appendFile(logFile, logEntry);
      this.currentLogSize += Buffer.byteLength(logEntry);
      
      // Check log size
      if (this.currentLogSize > CONFIG.MAX_LOG_SIZE_MB * 1024 * 1024) {
        await this.rotateLog(logFile);
      }
    } catch (err) {
      console.error('❌ Gagal menulis log:', err.message);
    }
  }

  async rotateLog(logFile) {
    try {
      const timestamp = Date.now();
      const newName = logFile.replace('.log', `.${timestamp}.log`);
      await fs.rename(logFile, newName);
      this.currentLogSize = 0;
      await this.log('INFO', 'Log dirotasi karena ukuran maksimal tercapai');
    } catch (err) {
      console.error('❌ Gagal rotasi log:', err.message);
    }
  }

  error(msg, meta) { return this.log('ERROR', msg, meta); }
  warn(msg, meta) { return this.log('WARN', msg, meta); }
  info(msg, meta) { return this.log('INFO', msg, meta); }
  success(msg, meta) { return this.log('SUCCESS', msg, meta); }
  debug(msg, meta) { return this.log('DEBUG', msg, meta); }
  security(msg, meta) { return this.log('SECURITY', msg, meta); }
  network(msg, meta) { return this.log('NETWORK', msg, meta); }
}

const logger = new Logger(path.join(__dirname, 'logs'));

// ========== MESSAGE QUEUE SYSTEM ==========
class MessageQueue {
  constructor() {
    this.queue = [];
    this.processing = false;
    this.metrics = {
      sent: 0,
      failed: 0,
      retried: 0
    };
  }

  async add(message) {
    this.queue.push({
      id: crypto.randomUUID(),
      ...message,
      attempts: 0,
      addedAt: Date.now()
    });
    
    if (!this.processing) {
      this.process();
    }
  }

  async process() {
    if (this.processing || this.queue.length === 0) return;
    
    this.processing = true;
    
    while (this.queue.length > 0) {
      const msg = this.queue[0];
      
      try {
        await this.sendMessage(msg);
        this.queue.shift();
        this.metrics.sent++;
        logger.success(`Pesan berhasil dikirim ke ${msg.to}`, { id: msg.id });
      } catch (err) {
        msg.attempts++;
        
        if (msg.attempts >= CONFIG.MESSAGE_RETRY_ATTEMPTS) {
          logger.error(`Pesan gagal setelah ${msg.attempts} percobaan ke ${msg.to}`, {
            id: msg.id,
            error: err.message
          });
          this.queue.shift();
          this.metrics.failed++;
        } else {
          logger.warn(`Percobaan ${msg.attempts} gagal ke ${msg.to}, retry...`, { id: msg.id });
          this.metrics.retried++;
          await this.sleep(CONFIG.MESSAGE_RETRY_DELAY_MS * msg.attempts);
        }
      }
    }
    
    this.processing = false;
  }

  async sendMessage(msg) {
    if (!sock || sock.ws?.readyState !== 1) {
      throw new Error('WhatsApp tidak terhubung');
    }
    
    const jid = msg.to.includes('@s.whatsapp.net') ? msg.to : `${msg.to}@s.whatsapp.net`;
    await sock.sendMessage(jid, { text: msg.message });
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  getMetrics() {
    return {
      ...this.metrics,
      queueLength: this.queue.length,
      processing: this.processing
    };
  }
}

const messageQueue = new MessageQueue();

// ========== RATE LIMITING ==========
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: CONFIG.MAX_LOGIN_ATTEMPTS,
  message: { status: false, message: '🔒 Terlalu banyak percobaan login. Coba lagi nanti.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.security('Login rate limit exceeded', { ip: req.ip });
    res.status(429).json({ 
      status: false, 
      message: '🔒 Terlalu banyak percobaan login. Coba lagi dalam 15 menit.' 
    });
  }
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { status: false, message: '⏱️ Terlalu banyak request. Coba lagi nanti.' },
  standardHeaders: true,
  legacyHeaders: false
});

const messageLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { status: false, message: '⏱️ Terlalu banyak pesan. Maksimal 30 pesan per menit.' }
});

// ========== INPUT VALIDATION ==========
function sanitizeInput(input, maxLength = 1000) {
  if (typeof input !== 'string') return '';
  return input.trim().substring(0, maxLength);
}

function validatePhoneNumber(phone) {
  const cleaned = phone.replace(/\D/g, '');
  return /^[1-9]\d{7,14}$/.test(cleaned);
}

function validateMessage(message) {
  if (!message || typeof message !== 'string') return false;
  if (message.length > 10000) return false;
  return true;
}

// ========== PASSWORD HASHING ==========
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function verifyPassword(inputPassword, hashedPassword) {
  const inputHash = hashPassword(inputPassword);
  return crypto.timingSafeEqual(
    Buffer.from(inputHash),
    Buffer.from(hashedPassword)
  );
}

// Hash password dari env saat startup
const HASHED_PASSWORD = hashPassword(CONFIG.LOGIN_PASSWORD);

// ========== EXPRESS APP SETUP ==========
const app = express();

// Security headers
app.use(helmet({
  contentSecurityPolicy: false, // Disable untuk dashboard
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

app.use(session({
  secret: CONFIG.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'wa_gateway_sid',
  cookie: { 
    maxAge: 1000 * 60 * 60 * 24,
    httpOnly: true,
    secure: false,  // Set to true only if using HTTPS
    sameSite: 'lax'  // Changed from 'strict' to 'lax' for better redirect handling
  }
}));

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (req.path !== '/health') {
      logger.network(`${req.method} ${req.path} ${res.statusCode} ${duration}ms`, {
        ip: req.ip,
        userAgent: req.get('user-agent')
      });
    }
  });
  next();
});

// ========== AUTH MIDDLEWARE ==========
function requireLogin(req, res, next) {
  if (req.session?.loggedIn) {
    logger.debug('Session valid, akses granted', { 
      username: req.session.username,
      path: req.path,
      sessionId: req.sessionID 
    });
    return next();
  }
  
  logger.debug('Session tidak valid, redirect ke login', { 
    path: req.path,
    hasSession: !!req.session,
    loggedIn: req.session?.loggedIn,
    sessionId: req.sessionID
  });
  
  res.redirect('/login');
}

function requireAuth(req, res, next) {
  const token = req.headers.authorization;
  if (!token || token !== `Bearer ${CONFIG.LARAVEL_API_KEY}`) {
    logger.security('Unauthorized API access attempt', { 
      ip: req.ip, 
      path: req.path,
      token: token ? 'present' : 'missing'
    });
    return res.status(401).json({ status: false, message: '🔒 Unauthorized' });
  }
  next();
}

// ========== WHATSAPP CONNECTION ==========
let sock;
let qrBase64 = null;
let qrLocked = false;
let qrLockTime = null;
let connectionMetrics = {
  connected: false,
  lastConnected: null,
  reconnectAttempts: 0,
  totalMessages: 0,
  errors: 0
};

function lockQR() {
  qrLocked = true;
  qrLockTime = Date.now();
}

function unlockQR(force = false) {
  if (force || (qrLockTime && Date.now() - qrLockTime > 30000)) {
    qrLocked = false;
    qrLockTime = null;
    logger.debug('QR unlocked');
  }
}

async function clearAuthFolder() {
  const folder = path.join(__dirname, 'auth');
  try {
    await fs.rm(folder, { recursive: true, force: true });
    logger.info('Folder auth dibersihkan');
  } catch (err) {
    logger.error('Gagal menghapus folder auth', { error: err.message });
  }
}

async function startSock() {
  try {
    const { state, saveCreds } = await useMultiFileAuthState('auth');
    const { version } = await fetchLatestBaileysVersion();

    sock = makeWASocket({
      version,
      auth: state,
      printQRInTerminal: true,
      defaultQueryTimeoutMs: 60000,
      keepAliveIntervalMs: 30000
    });

    sock.ev.on('connection.update', async (update) => {
      const { connection, qr, lastDisconnect } = update;

      if (qr && !qrLocked) {
        try {
          lockQR();
          qrBase64 = await qrcode.toDataURL(qr);
          
          // Save QR to file (async)
          const qrFile = path.join(__dirname, 'qr.tmp');
          await fs.writeFile(qrFile, qrBase64);
          
          logger.info('QR code berhasil dibuat', { locked: true });
          setTimeout(unlockQR, 30000);
        } catch (err) {
          logger.error('Gagal membuat QR code', { error: err.message });
        }
      }

      if (connection === 'open') {
        connectionMetrics.connected = true;
        connectionMetrics.lastConnected = new Date();
        connectionMetrics.reconnectAttempts = 0;
        
        logger.success('WhatsApp berhasil terhubung');
        
        setTimeout(async () => {
          qrBase64 = null;
          qrLocked = false;
          
          const qrFile = path.join(__dirname, 'qr.tmp');
          try {
            await fs.unlink(qrFile);
            logger.info('QR code dihapus setelah koneksi berhasil');
          } catch (err) {
            // File mungkin sudah tidak ada
          }
        }, 5000);
      }

      if (connection === 'close') {
        connectionMetrics.connected = false;
        connectionMetrics.reconnectAttempts++;
        
        const code = lastDisconnect?.error?.output?.statusCode;
        const reason = lastDisconnect?.error?.message || 'Unknown';
        
        logger.warn('Koneksi WhatsApp terputus', { code, reason });

        if (code === 401) {
          logger.security('Sesi tidak valid (401) - Membersihkan auth');
          await clearAuthFolder();
          setTimeout(startSock, 2000);
        } else if (code !== DisconnectReason.loggedOut) {
          const delay = Math.min(3000 * connectionMetrics.reconnectAttempts, 30000);
          logger.info(`Reconnect dalam ${delay}ms (attempt ${connectionMetrics.reconnectAttempts})`);
          setTimeout(startSock, delay);
        } else {
          logger.warn('User logout dari WhatsApp');
        }
      }
    });

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('messages.upsert', async ({ messages }) => {
      const msg = messages[0];
      if (!msg.message || msg.key.fromMe) return;

      connectionMetrics.totalMessages++;
      
      const from = msg.key.remoteJid;
      const body = msg.message?.conversation || msg.message?.extendedTextMessage?.text || '';
      const lower = body.toLowerCase().trim();

      const keywords = ['pinjam ruang', 'lihat ruang'];
      const matched = keywords.find(k => lower.includes(k));
      
      if (matched) {
        logger.info(`Keyword terdeteksi: "${matched}"`, { from, preview: body.substring(0, 50) });

        try {
          const response = await axios.post(
            CONFIG.LARAVEL_WEBHOOK_URL,
            {
              from,
              body,
              timestamp: msg.messageTimestamp,
              keyword: matched
            },
            {
              headers: {
                'Authorization': `Bearer ${CONFIG.LARAVEL_API_KEY}`,
                'Content-Type': 'application/json'
              },
              timeout: 10000
            }
          );
          
          logger.success(`Webhook berhasil (${response.status})`, { 
            from, 
            keyword: matched 
          });
        } catch (err) {
          connectionMetrics.errors++;
          logger.error('Gagal mengirim ke webhook', { 
            error: err.message,
            from,
            keyword: matched
          });
        }
      }
    });

    logger.success('WhatsApp socket initialized');
  } catch (err) {
    logger.error('Gagal inisialisasi WhatsApp socket', { error: err.message });
    setTimeout(startSock, 5000);
  }
}

// ========== LOG CLEANUP ==========
async function cleanupOldLogs() {
  try {
    const logsDir = path.join(__dirname, 'logs');
    const files = await fs.readdir(logsDir);
    
    const logFiles = await Promise.all(
      files
        .filter(file => file.startsWith('gateway-') && file.endsWith('.log'))
        .map(async file => {
          const fullPath = path.join(logsDir, file);
          const stats = await fs.stat(fullPath);
          return {
            name: file,
            path: fullPath,
            time: stats.mtime.getTime()
          };
        })
    );

    const now = Date.now();
    const retentionMs = CONFIG.LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;
    let deletedCount = 0;

    for (const file of logFiles) {
      if (now - file.time > retentionMs) {
        await fs.unlink(file.path);
        deletedCount++;
        logger.info(`Log lama dihapus: ${file.name}`);
      }
    }
    
    if (deletedCount > 0) {
      logger.success(`Cleanup selesai: ${deletedCount} log dihapus`);
    }
  } catch (err) {
    logger.error('Gagal cleanup log', { error: err.message });
  }
}

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
    scheduleLogCleanup();
  }, msToMidnight);
  
  logger.debug(`Cleanup log dijadwalkan dalam ${Math.round(msToMidnight / 1000 / 60)} menit`);
}

// ========== ROUTES ==========
app.get('/login', (req, res) => {
  if (req.session?.loggedIn) {
    logger.debug('User sudah login, redirect ke dashboard', { 
      username: req.session.username 
    });
    return res.redirect('/dashboard');
  }
  
  const htmlPath = path.join(__dirname, 'login.html');
  
  fsSync.readFile(htmlPath, 'utf8', (err, data) => {
    if (err) {
      logger.error('Gagal load login page', { error: err.message });
      return res.status(500).send('❌ Gagal memuat halaman login');
    }
    
    const rendered = data.replace('{{ERROR}}', req.query.error ? 'Username atau password salah' : '');
    res.send(rendered);
  });
});

app.post('/login', loginLimiter, (req, res) => {
  const username = sanitizeInput(req.body.username, 50);
  const password = sanitizeInput(req.body.password, 100);

  if (!username || !password) {
    logger.security('Login attempt dengan data kosong', { ip: req.ip });
    return res.redirect('/login?error=1');
  }

  if (username === CONFIG.LOGIN_USERNAME && verifyPassword(password, HASHED_PASSWORD)) {
    // Set session data sebelum regenerate
    req.session.loggedIn = true;
    req.session.username = username;
    
    logger.success('Login berhasil', { username, ip: req.ip });
    
    // Save session dan redirect
    req.session.save((err) => {
      if (err) {
        logger.error('Session save error', { error: err.message });
        return res.redirect('/login?error=1');
      }
      res.redirect('/dashboard');
    });
  } else {
    logger.security('Login gagal - kredensial salah', { username, ip: req.ip });
    res.redirect('/login?error=1');
  }
});

app.post('/logout', requireLogin, (req, res) => {
  const username = req.session.username;
  req.session.destroy(() => {
    logger.info('User logout', { username });
    res.redirect('/login');
  });
});

app.get('/dashboard', requireLogin, (req, res) => {
  const htmlPath = path.join(__dirname, 'dashboard.html');
  
  fsSync.readFile(htmlPath, 'utf8', (err, data) => {
    if (err) {
      logger.error('Gagal load dashboard', { error: err.message });
      return res.status(500).send('❌ Gagal memuat dashboard');
    }
    
    const rendered = data.replace('{{LARAVEL_API_KEY}}', CONFIG.LARAVEL_API_KEY || '');
    res.send(rendered);
  });
});

app.get('/broadcast', requireLogin, (req, res) => {
  const htmlPath = path.join(__dirname, 'pesan.html');
  
  fsSync.readFile(htmlPath, 'utf8', (err, data) => {
    if (err) {
      logger.error('Gagal load broadcast page', { error: err.message });
      return res.status(500).send('❌ Gagal memuat halaman broadcast');
    }
    
    const rendered = data.replace('{{LARAVEL_API_KEY}}', CONFIG.LARAVEL_API_KEY || '');
    res.send(rendered);
  });
});

app.get('/qr', requireAuth, apiLimiter, (req, res) => {
  if (qrBase64) {
    logger.debug('QR code dikirim');
    return res.json({ status: true, qr: qrBase64 });
  }
  return res.json({ status: false, qr: null, message: 'QR tidak tersedia' });
});

app.get('/logs', requireAuth, apiLimiter, async (req, res) => {
  try {
    const logsDir = path.join(__dirname, 'logs');
    const logFileName = logger.getLogFileName();
    
    const data = await fs.readFile(logFileName, 'utf8');
    const lines = data.trim().split('\n').slice(-200).join('\n');
    
    res.json({ status: true, log: lines });
  } catch (err) {
    logger.error('Gagal membaca log', { error: err.message });
    res.json({ status: false, log: '', message: 'Belum ada log hari ini' });
  }
});

app.get('/logs/list', requireAuth, apiLimiter, async (req, res) => {
  try {
    const logsDir = path.join(__dirname, 'logs');
    const files = await fs.readdir(logsDir);
    
    const logFiles = await Promise.all(
      files
        .filter(file => file.startsWith('gateway-') && file.endsWith('.log'))
        .map(async file => {
          const fullPath = path.join(logsDir, file);
          const stats = await fs.stat(fullPath);
          return {
            name: file,
            date: file.replace('gateway-', '').replace('.log', ''),
            size: stats.size,
            modified: stats.mtime,
            sizeFormatted: (stats.size / 1024).toFixed(2) + ' KB'
          };
        })
    );
    
    logFiles.sort((a, b) => b.modified - a.modified);
    
    res.json({ status: true, logs: logFiles });
  } catch (err) {
    logger.error('Gagal list log files', { error: err.message });
    res.status(500).json({ status: false, message: err.message });
  }
});

app.get('/logs/download/:date', requireAuth, (req, res) => {
  const date = sanitizeInput(req.params.date, 20);
  
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    logger.security('Invalid date format in log download', { date, ip: req.ip });
    return res.status(400).json({ status: false, message: 'Format tanggal tidak valid' });
  }
  
  const logsDir = path.join(__dirname, 'logs');
  const logFile = path.join(logsDir, `gateway-${date}.log`);
  
  if (!fsSync.existsSync(logFile)) {
    return res.status(404).json({ status: false, message: 'Log tidak ditemukan' });
  }
  
  logger.info(`Log downloaded: ${date}`, { ip: req.ip });
  res.download(logFile);
});

// CRITICAL: Tetap menggunakan /send-message dan LARAVEL_API_KEY untuk backward compatibility
app.post('/send-message', requireAuth, messageLimiter, async (req, res) => {
  const { to, message } = req.body;

  if (!to || !message) {
    return res.status(400).json({ 
      status: false, 
      message: '❌ Parameter to dan message wajib diisi' 
    });
  }

  const sanitizedTo = sanitizeInput(to, 20);
  const sanitizedMessage = sanitizeInput(message, 10000);

  if (!validatePhoneNumber(sanitizedTo.replace('@s.whatsapp.net', ''))) {
    return res.status(400).json({ 
      status: false, 
      message: '❌ Nomor telepon tidak valid' 
    });
  }

  if (!validateMessage(sanitizedMessage)) {
    return res.status(400).json({ 
      status: false, 
      message: '❌ Pesan tidak valid atau terlalu panjang (max 10000 karakter)' 
    });
  }

  try {
    // Add to queue
    await messageQueue.add({
      to: sanitizedTo,
      message: sanitizedMessage
    });

    logger.info(`Pesan ditambahkan ke queue untuk ${sanitizedTo}`);
    
    res.json({ 
      status: true, 
      message: '✅ Pesan berhasil ditambahkan ke antrian pengiriman' 
    });
  } catch (err) {
    logger.error('Gagal menambahkan pesan ke queue', { 
      error: err.message,
      to: sanitizedTo 
    });
    res.status(500).json({ 
      status: false, 
      message: '❌ Gagal menambahkan pesan ke antrian',
      error: err.message 
    });
  }
});

app.post('/restart', requireAuth, async (req, res) => {
  try {
    logger.warn('Restart gateway diminta via API', { ip: req.ip });
    res.json({ status: true, message: '🔄 Gateway sedang direstart...' });
    
    setTimeout(() => {
      exec(`pm2 restart ${CONFIG.PM2_APP_NAME}`, (error, stdout, stderr) => {
        if (error) {
          logger.error('PM2 restart gagal', { error: error.message });
          return;
        }
        if (stderr) logger.warn('PM2 restart stderr', { stderr });
        logger.success('PM2 restart berhasil', { stdout });
      });
    }, 500);
  } catch (err) {
    logger.error('Gagal restart gateway', { error: err.message });
    res.status(500).json({ 
      status: false, 
      message: '❌ Gagal restart gateway',
      error: err.message 
    });
  }
});

app.get('/health', apiLimiter, (req, res) => {
  const memUsage = process.memoryUsage();
  const uptime = process.uptime();
  
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    connection: {
      whatsapp: sock?.ws?.readyState === 1 ? 'connected' : 'disconnected',
      ...connectionMetrics
    },
    memory: {
      rss: `${(memUsage.rss / 1024 / 1024).toFixed(2)} MB`,
      heapUsed: `${(memUsage.heapUsed / 1024 / 1024).toFixed(2)} MB`,
      heapTotal: `${(memUsage.heapTotal / 1024 / 1024).toFixed(2)} MB`,
      external: `${(memUsage.external / 1024 / 1024).toFixed(2)} MB`
    },
    uptime: {
      seconds: Math.floor(uptime),
      formatted: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`
    },
    messageQueue: messageQueue.getMetrics(),
    system: {
      platform: os.platform(),
      arch: os.arch(),
      nodeVersion: process.version,
      cpuCount: os.cpus().length,
      totalMemory: `${(os.totalmem() / 1024 / 1024 / 1024).toFixed(2)} GB`,
      freeMemory: `${(os.freemem() / 1024 / 1024 / 1024).toFixed(2)} GB`
    }
  });
});

app.get('/metrics', requireAuth, (req, res) => {
  res.json({
    timestamp: new Date().toISOString(),
    connection: connectionMetrics,
    messageQueue: messageQueue.getMetrics(),
    process: {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage()
    }
  });
});

app.get('/', (req, res) => {
  res.redirect('/dashboard');
});

// 404 Handler
app.use((req, res) => {
  logger.warn('404 Not Found', { path: req.path, ip: req.ip });
  res.status(404).json({ 
    status: false, 
    message: '❌ Endpoint tidak ditemukan' 
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { 
    error: err.message,
    stack: err.stack,
    path: req.path
  });
  
  res.status(500).json({ 
    status: false, 
    message: '❌ Terjadi kesalahan server',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ========== PROCESS HANDLERS ==========
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Promise Rejection', { 
    reason: reason?.toString(),
    stack: reason?.stack 
  });
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception', { 
    error: err.message,
    stack: err.stack 
  });
  
  // Graceful shutdown
  setTimeout(() => {
    process.exit(1);
  }, 1000);
});

process.on('SIGTERM', async () => {
  logger.warn('SIGTERM signal received - Shutting down gracefully');
  
  // Close WhatsApp connection
  if (sock) {
    try {
      await sock.logout();
      logger.info('WhatsApp logged out');
    } catch (err) {
      logger.error('Error logging out WhatsApp', { error: err.message });
    }
  }
  
  // Wait for queue to finish
  let waitCount = 0;
  while (messageQueue.queue.length > 0 && waitCount < 30) {
    logger.info(`Waiting for message queue to finish... (${messageQueue.queue.length} remaining)`);
    await new Promise(resolve => setTimeout(resolve, 1000));
    waitCount++;
  }
  
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.warn('SIGINT signal received - Shutting down');
  process.exit(0);
});

// ========== UTILITY FUNCTIONS ==========
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

// ========== STARTUP ==========
async function startServer() {
  try {
    // Cleanup old logs on startup
    await cleanupOldLogs();
    
    // Schedule daily cleanup
    scheduleLogCleanup();
    
    // Start WhatsApp socket
    await startSock();
    
    // Start Express server
    const host = getLocalIp();
    app.listen(CONFIG.PORT, () => {
      const banner = `
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║  🚀 WhatsApp Gateway API - ENHANCED VERSION              ║
║                                                           ║
║  Server    : http://${host}:${CONFIG.PORT.toString().padEnd(37)} ║
║  Dashboard : http://${host}:${CONFIG.PORT}/dashboard${' '.repeat(24)} ║
║  Health    : http://${host}:${CONFIG.PORT}/health${' '.repeat(27)} ║
║                                                           ║
║  Status    : ✅ Running                                   ║
║  Node      : ${process.version.padEnd(44)} ║
║  Memory    : ${((process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2) + ' MB').padEnd(44)} ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
      `;
      
      console.log(banner);
      logger.success('Server berhasil dijalankan', { 
        host, 
        port: CONFIG.PORT,
        nodeVersion: process.version 
      });
    });
    
  } catch (err) {
    logger.error('Gagal start server', { error: err.message });
    process.exit(1);
  }
}

// Start the server
startServer();

// ========== MONITORING INTERVAL ==========
setInterval(() => {
  const memUsage = process.memoryUsage();
  const heapUsedMB = (memUsage.heapUsed / 1024 / 1024).toFixed(2);
  
  // Log metrics every 5 minutes
  logger.debug('System metrics', {
    heap: `${heapUsedMB} MB`,
    queueLength: messageQueue.queue.length,
    connected: connectionMetrics.connected,
    totalMessages: connectionMetrics.totalMessages
  });
  
  // Warning if memory usage is high
  if (memUsage.heapUsed > 500 * 1024 * 1024) { // 500MB
    logger.warn('Memory usage tinggi', { heap: `${heapUsedMB} MB` });
  }
  
}, 5 * 60 * 1000); // Every 5 minutes