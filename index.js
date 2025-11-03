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
  MAX_MESSAGE_PER_MINUTE: parseInt(process.env.MAX_MESSAGE_PER_MINUTE) || 500,
  MESSAGE_RETRY_DELAY_MS: parseInt(process.env.MESSAGE_RETRY_DELAY_MS) || 2000,
  LOG_RETENTION_DAYS: parseInt(process.env.LOG_RETENTION_DAYS) || 14,
  MAX_LOG_SIZE_MB: parseInt(process.env.MAX_LOG_SIZE_MB) || 10
};

const EventEmitter = require('events');
const loginEmitter = new EventEmitter();

// Track status dengan lebih detail
let sessionState = {
  dashboardLoggedIn: false,
  whatsappConnected: false,
  greetingSent: false,
  lastLoginTime: null
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

// ============ METRICS JSON MANAGEMENT ============

const METRICS_FILE = path.join(__dirname, 'metrics.json');

// Simpan metrics ke file JSON
async function saveMetricsToFile(metrics) {
  try {
    await fs.writeFile(METRICS_FILE, JSON.stringify(metrics, null, 2), 'utf-8');
    logger.debug('Metrics disimpan ke file', { file: METRICS_FILE });
  } catch (err) {
    logger.error('Gagal menyimpan metrics ke file', { error: err.message });
  }
}

// Baca metrics dari file JSON
async function loadMetricsFromFile() {
  try {
    if (fsSync.existsSync(METRICS_FILE)) {
      const data = await fs.readFile(METRICS_FILE, 'utf-8');
      const metrics = JSON.parse(data);
      logger.debug('Metrics dimuat dari file', { file: METRICS_FILE });
      return metrics;
    }
  } catch (err) {
    logger.warn('Gagal memuat metrics dari file', { error: err.message });
  }
  return null;
}

// Hapus file metrics.json
async function deleteMetricsFile() {
  try {
    if (fsSync.existsSync(METRICS_FILE)) {
      await fs.unlink(METRICS_FILE);
      logger.debug('File metrics.json dihapus', { file: METRICS_FILE });
    }
  } catch (err) {
    logger.error('Gagal menghapus metrics.json', { error: err.message });
  }
}

// ========== LOGGING SYSTEM WITH LEVELS (JAKARTA TIME) ==========
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
  RESTART: '🔄',
  QUEUE: '📊'
};

class EnhancedLogger {
  constructor(logsDir) {
    this.logsDir = logsDir;
    this.currentLogSizes = {};
    this.initLogsDir();
  }

  async initLogsDir() {
    try {
      await fs.mkdir(this.logsDir, { recursive: true });
    } catch (err) {
      console.error('❌ Gagal membuat direktori logs:', err.message);
    }
  }

  // 🕒 Format tanggal pakai zona waktu Asia/Jakarta
  getFormattedTimestamp() {
    const options = {
      timeZone: 'Asia/Jakarta',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    };
    const now = new Date().toLocaleString('sv-SE', options); // hasil: YYYY-MM-DD HH:mm:ss
    return now.replace('T', ' ');
  }

  getLogFileName(type = 'activity') {
    const now = new Date();
    const options = { timeZone: 'Asia/Jakarta' };
    const yyyy = new Intl.DateTimeFormat('en-CA', { ...options, year: 'numeric' }).format(now);
    const MM = new Intl.DateTimeFormat('en-CA', { ...options, month: '2-digit' }).format(now);
    const dd = new Intl.DateTimeFormat('en-CA', { ...options, day: '2-digit' }).format(now);
    return path.join(this.logsDir, `${type}-${yyyy}-${MM}-${dd}.log`);
  }

  async _appendToFile(filePath, entry) {
    try {
      await fs.appendFile(filePath, entry);
      const byteLen = Buffer.byteLength(entry);
      this.currentLogSizes[filePath] = (this.currentLogSizes[filePath] || 0) + byteLen;

      if (this.currentLogSizes[filePath] > CONFIG.MAX_LOG_SIZE_MB * 1024 * 1024) {
        await this.rotateLog(filePath);
      }
    } catch (err) {
      console.error('❌ Gagal menulis log ke', filePath, err.message);
    }
  }

  async log(level, message, metadata = {}, logType = 'activity') {
    const icon = LOG_LEVELS[level] || 'ℹ️';
    const timestamp = this.getFormattedTimestamp();

    const metaStr =
      Object.keys(metadata).length > 0 ? ` | ${JSON.stringify(metadata)}` : '';

    const logEntry = `[${timestamp}] [${level}] ${icon} ${message}${metaStr}\n`;

    // Tentukan file log
    let logFile;
    if (logType === 'network') {
      logFile = this.getLogFileName('network');
    } else {
      logFile = this.getLogFileName('activity');
      console.log(logEntry.trim());
    }

    await this._appendToFile(logFile, logEntry);
  }

  async rotateLog(logFile) {
    try {
      const timestamp = Date.now();
      const newName = logFile.replace('.log', `.${timestamp}.log`);
      await fs.rename(logFile, newName);
      this.currentLogSizes[logFile] = 0;
      const rotationNote = `[${this.getFormattedTimestamp()}] [INFO] ℹ️ Log dirotasi karena ukuran maksimal tercapai\n`;
      await this._appendToFile(logFile, rotationNote);
    } catch (err) {
      console.error('❌ Gagal rotasi log:', err.message);
    }
  }

  // ===== Shortcut Methods =====
  error(msg, meta) { return this.log('ERROR', msg, meta, 'activity'); }
  warn(msg, meta) { return this.log('WARN', msg, meta, 'activity'); }
  info(msg, meta) { return this.log('INFO', msg, meta, 'activity'); }
  success(msg, meta) { return this.log('SUCCESS', msg, meta, 'activity'); }
  security(msg, meta) { return this.log('SECURITY', msg, meta, 'activity'); }
  message(msg, meta) { return this.log('MESSAGE', msg, meta, 'activity'); }
  qr(msg, meta) { return this.log('QR', msg, meta, 'activity'); }
  cleanup(msg, meta) { return this.log('CLEANUP', msg, meta, 'activity'); }
  restart(msg, meta) { return this.log('RESTART', msg, meta, 'activity'); }
  queue(msg, meta) { return this.log('QUEUE', msg, meta, 'activity'); }
  network(msg, meta) { return this.log('NETWORK', msg, meta, 'network'); }
  debug(msg, meta) { return this.log('DEBUG', msg, meta, 'network'); }
}
const logger = new EnhancedLogger(path.join(__dirname, 'logs'));

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
    
    // SESUDAH (reliable, menggunakan metrics + user.id)
    if (!sock || !connectionMetrics.connected) {
    throw new Error('WhatsApp tidak terhubung');
    }
    
    // Double check dengan user.id (indikator pasti sudah login)
    if (!sock.user || !sock.user.id) {
      throw new Error('WhatsApp belum terotentikasi');
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
  max: CONFIG.MAX_MESSAGE_PER_MINUTE || 500,
  message: { status: false, message: '⏱️ Terlalu banyak pesan. Maksimal 500 pesan per menit.' }
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
// Update metrics dan simpan ke file
async function updateMetrics() {
  const memUsage = process.memoryUsage();
  const uptime = process.uptime();
  
  const metrics = {
    timestamp: new Date().toISOString(),
    connection: {
      whatsapp: connectionMetrics.connected && sock && sock.user && sock.user.id ? 'connected' : 'disconnected',
      ...connectionMetrics,
      user: sock?.user ? {
        id: sock.user.id,
        name: sock.user.name
      } : null,
      totalMessages: connectionMetrics.totalMessages + messageQueue.metrics.sent
    },
    messageQueue: messageQueue.getMetrics(),
    process: {
      uptime: {
        seconds: Math.floor(uptime),
        formatted: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`
      },
      memory: {
        rss: `${(memUsage.rss / 1024 / 1024).toFixed(2)} MB`,
        heapUsed: `${(memUsage.heapUsed / 1024 / 1024).toFixed(2)} MB`,
        heapTotal: `${(memUsage.heapTotal / 1024 / 1024).toFixed(2)} MB`,
        external: `${(memUsage.external / 1024 / 1024).toFixed(2)} MB`
      }
    },
    system: {
      platform: os.platform(),
      arch: os.arch(),
      nodeVersion: process.version,
      cpuCount: os.cpus().length,
      totalMemory: `${(os.totalmem() / 1024 / 1024 / 1024).toFixed(2)} GB`,
      freeMemory: `${(os.freemem() / 1024 / 1024 / 1024).toFixed(2)} GB`
    }
  };
  
  await saveMetricsToFile(metrics);
  return metrics;
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
        // Update dan simpan metrics saat terhubung
        await updateMetrics();

        // ✅ KIRIM PESAN SAMBUTAN HANYA JIKA:
        // 1. User sudah login ke dashboard
        // 2. Pesan belum pernah dikirim dalam sesi ini
        // 3. Koneksi baru saja terbentuk (bukan reconnect lama)
        const shouldSendGreeting = 
          sessionState.dashboardLoggedIn && 
          !sessionState.greetingSent &&
          sock.user?.id;

        if (shouldSendGreeting) {
          try {
            await sock.sendMessage(sock.user.id, { 
              text: `🤖 *WhatsApp Gateway Aktif*\n\n✅ Koneksi berhasil pada ${new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })}\n📱 Siap menerima dan mengirim pesan!` 
            });
            
            sessionState.greetingSent = true;
            logger.success('Pesan sambutan terkirim ke user', { 
              jid: sock.user.id,
              dashboardLogin: sessionState.dashboardLoggedIn 
            });
          } catch (error) {
            logger.error('Gagal mengirim pesan sambutan', { error: error.message });
          }
        } else {
          logger.info('Pesan sambutan tidak dikirim', { 
            dashboardLoggedIn: sessionState.dashboardLoggedIn,
            greetingSent: sessionState.greetingSent,
            hasUserId: !!sock.user?.id
          });
        }
        
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
        sessionState.whatsappConnected = false;
        sessionState.greetingSent = false; // Reset agar bisa kirim lagi saat reconnect
        
        const code = lastDisconnect?.error?.output?.statusCode;
        const reason = lastDisconnect?.error?.message || 'Unknown';
        
        logger.warn('Koneksi WhatsApp terputus', { code, reason });
                // HAPUS METRICS FILE SAAT KONEKSI DITUTUP
        await deleteMetricsFile();

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

            // Update metrics setiap ada pesan masuk
      await updateMetrics();
      
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

// ========== LOG CLEANUP - FIXED VERSION ==========
let logCleanupTimer = null; // Track timer global

async function cleanupOldLogs() {
  try {
    const logsDir = path.join(__dirname, 'logs');
    const files = await fs.readdir(logsDir);
    
    const logFiles = await Promise.all(
      files
        .filter(file => /^(activity|network)-\d{4}-\d{2}-\d{2}\.log$/.test(file))
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
  // ✅ CLEAR TIMER LAMA SEBELUM BUAT BARU
  if (logCleanupTimer) {
    clearTimeout(logCleanupTimer);
    logger.debug('Timer cleanup log lama dibersihkan');
  }

  const now = new Date();
  const night = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate() + 1,
    0, 0, 0
  );
  const msToMidnight = night.getTime() - now.getTime();

  logCleanupTimer = setTimeout(() => {
    cleanupOldLogs();
    scheduleLogCleanup(); // Reschedule untuk hari berikutnya
  }, msToMidnight);
  
  logger.info(`Cleanup log dijadwalkan dalam ${Math.round(msToMidnight / 1000 / 60)} menit`); // ✅ Ubah ke INFO agar terlihat
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

    // ✅ SET STATUS LOGIN DAN TIMESTAMP
    sessionState.dashboardLoggedIn = true;
    sessionState.lastLoginTime = new Date();
    sessionState.greetingSent = false; // Reset untuk login baru
    
    logger.success('Login berhasil', { username, ip: req.ip });
    
     // ✅ JIKA WHATSAPP SUDAH CONNECT, KIRIM PESAN SEKARANG
    if (sessionState.whatsappConnected && sock?.user?.id) {
      try {
        sock.sendMessage(sock.user.id, { 
          text: `🤖 *Dashboard Login Terdeteksi*\n\n👤 User: ${username}\n🕐 ${new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })}\n✅ Gateway siap digunakan!` 
        });
        
        sessionState.greetingSent = true;
        logger.success('Pesan sambutan terkirim saat login', { 
          username,
          jid: sock.user.id 
        });
      } catch (error) {
        logger.error('Gagal mengirim pesan sambutan saat login', { error: error.message });
      }
    }


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
   // ✅ RESET SESSION STATE
  sessionState.dashboardLoggedIn = false;
  sessionState.greetingSent = false;
  sessionState.lastLoginTime = null;

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

// ========== ENHANCED LOG ENDPOINTS ==========

// 🔹 GET LOGS ACTIVITY ONLY
app.get('/logs/activity', requireAuth, apiLimiter, async (req, res) => {
  try {
    const activityLogFile = logger.getLogFileName('activity');
    const linesToShow = parseInt(req.query.lines) || 200;

    let activityData = '';
    if (fsSync.existsSync(activityLogFile)) {
      activityData = (await fs.readFile(activityLogFile, 'utf8')).trim();
    }

    const tail = (text, n) => {
      if (!text) return '';
      const arr = text.split('\n');
      return arr.slice(-n).join('\n');
    };

    const activityLog = tail(activityData, linesToShow);

    res.json({ 
      status: true, 
      log: activityLog,
      file: path.basename(activityLogFile),
      totalLines: activityData ? activityData.split('\n').length : 0,
      showing: Math.min(linesToShow, activityData ? activityData.split('\n').length : 0)
    });
  } catch (err) {
    logger.error('Gagal membaca log aktivitas', { error: err.message });
    res.json({ 
      status: false, 
      log: '', 
      message: 'Belum ada log aktivitas hari ini' 
    });
  }
});

// 🔹 GET LOGS NETWORK ONLY  
app.get('/logs/network', requireAuth, apiLimiter, async (req, res) => {
  try {
    const networkLogFile = logger.getLogFileName('network');
    const linesToShow = parseInt(req.query.lines) || 200;

    let networkData = '';
    if (fsSync.existsSync(networkLogFile)) {
      networkData = (await fs.readFile(networkLogFile, 'utf8')).trim();
    }

    const tail = (text, n) => {
      if (!text) return '';
      const arr = text.split('\n');
      return arr.slice(-n).join('\n');
    };

    const networkLog = tail(networkData, linesToShow);

    res.json({ 
      status: true, 
      log: networkLog,
      file: path.basename(networkLogFile),
      totalLines: networkData ? networkData.split('\n').length : 0,
      showing: Math.min(linesToShow, networkData ? networkData.split('\n').length : 0)
    });
  } catch (err) {
    logger.error('Gagal membaca log network', { error: err.message });
    res.json({ 
      status: false, 
      log: '', 
      message: 'Belum ada log network hari ini' 
    });
  }
});

// 🔹 GET BOTH LOGS (for backward compatibility)
app.get('/logs', requireAuth, apiLimiter, async (req, res) => {
  try {
    const activityLogFile = logger.getLogFileName('activity');
    const networkLogFile = logger.getLogFileName('network');
    const linesToShow = 100; // less for combined view

    let activityData = '';
    let networkData = '';

    if (fsSync.existsSync(activityLogFile)) {
      activityData = (await fs.readFile(activityLogFile, 'utf8')).trim();
    }

    if (fsSync.existsSync(networkLogFile)) {
      networkData = (await fs.readFile(networkLogFile, 'utf8')).trim();
    }

    const tail = (text, n) => {
      if (!text) return '';
      const arr = text.split('\n');
      return arr.slice(-n).join('\n');
    };

    const combined = [
      '=== ACTIVITY LOG ===',
      tail(activityData, Math.floor(linesToShow / 2)),
      '=== NETWORK LOG ===', 
      tail(networkData, Math.ceil(linesToShow / 2))
    ].join('\n');

    res.json({ 
      status: true, 
      log: combined,
      activityLines: activityData ? activityData.split('\n').length : 0,
      networkLines: networkData ? networkData.split('\n').length : 0
    });
  } catch (err) {
    logger.error('Gagal membaca logs', { error: err.message });
    res.json({ 
      status: false, 
      log: '', 
      message: 'Belum ada log hari ini' 
    });
  }
});

// 🔹 LIST LOG FILES
app.get('/logs/list', requireAuth, apiLimiter, async (req, res) => {
  try {
    const logsDir = path.join(__dirname, 'logs');
    const files = await fs.readdir(logsDir);

    const logFiles = await Promise.all(
      files
        .filter(file => /^(activity|network)-\d{4}-\d{2}-\d{2}\.log$/.test(file))
        .map(async file => {
          const fullPath = path.join(logsDir, file);
          const stats = await fs.stat(fullPath);

          const type = file.startsWith('network-') ? 'network' : 'activity';
          const date = file.replace('activity-', '').replace('network-', '').replace('.log', '');

          return {
            name: file,
            type: type,
            date: date,
            size: stats.size,
            modified: stats.mtime,
            sizeFormatted: (stats.size / 1024).toFixed(2) + ' KB',
            lines: await countFileLines(fullPath)
          };
        })
    );

    // Urutkan berdasarkan waktu modifikasi terbaru
    logFiles.sort((a, b) => b.modified - a.modified);

    res.json({ status: true, logs: logFiles });
  } catch (err) {
    logger.error('Gagal list log files', { error: err.message });
    res.status(500).json({ status: false, message: 'Gagal memuat daftar log' });
  }
});

// Helper function to count lines in file
async function countFileLines(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return data.split('\n').length;
  } catch {
    return 0;
  }
}

// 🔹 DOWNLOAD SPECIFIC LOG FILE
app.get('/logs/download/:type/:date', requireAuth, (req, res) => {
  const type = sanitizeInput(req.params.type, 10).toLowerCase();
  const date = sanitizeInput(req.params.date, 20);

  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    logger.security('Invalid date format in log download', { date, ip: req.ip });
    return res.status(400).json({ status: false, message: 'Format tanggal tidak valid' });
  }

  if (!['activity', 'network'].includes(type)) {
    logger.security('Invalid log type in download request', { type, ip: req.ip });
    return res.status(400).json({ status: false, message: 'Tipe log tidak valid' });
  }

  const logsDir = path.join(__dirname, 'logs');
  const fileName = `${type}-${date}.log`;
  const logFile = path.join(logsDir, fileName);

  if (!fsSync.existsSync(logFile)) {
    return res.status(404).json({ status: false, message: 'Log tidak ditemukan' });
  }

  logger.info(`Log ${type} diunduh: ${date}`, { ip: req.ip });
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

     // Update metrics setelah menambahkan pesan ke queue
    await updateMetrics();
    
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
  const waConnected = connectionMetrics.connected && sock && sock.user && sock.user.id;

  
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    connection: {
     whatsapp: waConnected ? 'connected' : 'disconnected',
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

// 🔹 ENDPOINT METRICS - AMBIL DARI FILE JSON
app.get('/metrics', requireAuth, async (req, res) => {
  try {
    // Coba load dari file terlebih dahulu
    const metricsFromFile = await loadMetricsFromFile();
    
    if (metricsFromFile) {
      logger.debug('Metrics dikirim dari file JSON');
      return res.json(metricsFromFile);
    }
    
    // Jika file tidak ada, generate metrics baru dan simpan
    logger.debug('File metrics tidak ditemukan, generate baru');
    const metrics = await updateMetrics();
    res.json(metrics);
    
  } catch (err) {
    logger.error('Gagal mendapatkan metrics', { error: err.message });
    res.status(500).json({ 
      status: false, 
      message: '❌ Gagal mendapatkan metrics',
      error: err.message 
    });
  }
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

// ========== PROCESS HANDLERS - UPDATED ==========
process.on('SIGTERM', async () => {
  logger.warn('SIGTERM signal received - Shutting down gracefully');
  
  // ✅ CLEANUP TIMERS
  if (logCleanupTimer) {
    clearTimeout(logCleanupTimer);
    logger.debug('Cleanup timer cleared');
  }
  
  if (monitoringInterval) {
    clearInterval(monitoringInterval);
    logger.debug('Monitoring interval cleared');
  }
  
  await deleteMetricsFile();

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
  
  // ✅ CLEANUP TIMERS
  if (logCleanupTimer) clearTimeout(logCleanupTimer);
  if (monitoringInterval) clearInterval(monitoringInterval);
  
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

// ========== MONITORING INTERVAL - FIXED ==========
let monitoringInterval = null; // Track interval global

function startMonitoring() {
  // ✅ CLEAR INTERVAL LAMA
  if (monitoringInterval) {
    clearInterval(monitoringInterval);
    logger.debug('Monitoring interval lama dibersihkan');
  }

  monitoringInterval = setInterval(async () => {
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

    // Update metrics setiap 5 menit jika terhubung
    if (connectionMetrics.connected && sock && sock.user) {
      await updateMetrics();
    }
  }, 5 * 60 * 1000); // Every 5 minutes
  
  logger.info('Monitoring interval started (5 menit)');
}


// ========== STARTUP - UPDATED ==========
async function startServer() {
  try {
    // Cleanup old logs on startup
    await cleanupOldLogs();
    
    // ✅ Schedule daily cleanup (HANYA SEKALI)
    scheduleLogCleanup();
    
    // ✅ Start monitoring (HANYA SEKALI)
    startMonitoring();
    
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

