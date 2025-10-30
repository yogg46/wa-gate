// ========== SERVER.JS - FIXED VERSION ==========
require('dotenv').config();

const {
  default: makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  DisconnectReason,
  delay,
  Browsers
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
  MAX_LOG_SIZE_MB: parseInt(process.env.MAX_LOG_SIZE_MB) || 10,
  MESSAGE_TIMEOUT_MS: parseInt(process.env.MESSAGE_TIMEOUT_MS) || 30000,
  MAX_QUEUE_SIZE: parseInt(process.env.MAX_QUEUE_SIZE) || 1000
};

// Validasi environment variables
function validateEnv() {
  const required = ['LOGIN_USERNAME', 'LOGIN_PASSWORD', 'LARAVEL_API_KEY', 'LARAVEL_WEBHOOK_URL'];
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    console.error(`❌ Environment variable wajib tidak ditemukan: ${missing.join(', ')}`);
    process.exit(1);
  }
}

validateEnv();

// ========== ENHANCED LOGGING SYSTEM ==========
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

  getFormattedTimestamp() {
    return new Date().toISOString().replace('T', ' ').substring(0, 19);
  }

  getLogFileName(type = 'activity') {
    const now = new Date();
    const dateStr = now.toISOString().split('T')[0];
    return path.join(this.logsDir, `${type}-${dateStr}.log`);
  }

  async log(level, message, metadata = {}, logType = 'activity') {
    const icons = {
      ERROR: '❌', WARN: '⚠️', INFO: 'ℹ️', SUCCESS: '✅', DEBUG: '🔍',
      SECURITY: '🔐', NETWORK: '🌐', MESSAGE: '📨', QR: '📸',
      CLEANUP: '🗑️', RESTART: '🔄', QUEUE: '📊', CONNECTION: '🔗'
    };
    
    const icon = icons[level] || 'ℹ️';
    const timestamp = this.getFormattedTimestamp();
    const metaStr = Object.keys(metadata).length > 0 ? ` | ${JSON.stringify(metadata)}` : '';
    const logEntry = `[${timestamp}] [${level}] ${icon} ${message}${metaStr}\n`;

    // Always show in console
    console.log(logEntry.trim());

    // Write to log file
    const logFile = this.getLogFileName(logType);
    try {
      await fs.appendFile(logFile, logEntry);
    } catch (err) {
      console.error('❌ Gagal menulis log:', err.message);
    }
  }

  // Log methods
  error(msg, meta) { return this.log('ERROR', msg, meta); }
  warn(msg, meta) { return this.log('WARN', msg, meta); }
  info(msg, meta) { return this.log('INFO', msg, meta); }
  success(msg, meta) { return this.log('SUCCESS', msg, meta); }
  debug(msg, meta) { return this.log('DEBUG', msg, meta); }
  connection(msg, meta) { return this.log('CONNECTION', msg, meta); }
  message(msg, meta) { return this.log('MESSAGE', msg, meta); }
  queue(msg, meta) { return this.log('QUEUE', msg, meta); }
}

const logger = new EnhancedLogger(path.join(__dirname, 'logs'));

// ========== FIXED MESSAGE QUEUE SYSTEM ==========
class FixedMessageQueue {
  constructor() {
    this.queue = [];
    this.processing = false;
    this.processingPaused = true; // Start paused until connection is ready
    this.metrics = {
      sent: 0,
      failed: 0,
      retried: 0,
      totalAdded: 0
    };
    this.sock = null; // Will be set after socket initialization
  }

  setSocket(whatsappSocket) {
    this.sock = whatsappSocket;
    logger.connection('Socket di-set ke MessageQueue', { 
      hasSocket: !!whatsappSocket,
      hasUser: !!whatsappSocket?.user?.id 
    });
  }

  isConnected() {
    if (!this.sock) {
      logger.connection('No socket instance available');
      return false;
    }

    try {
      // Comprehensive connection check
      const wsConnected = this.sock.ws && this.sock.ws.readyState === 1;
      const userLogged = !!(this.sock.user && this.sock.user.id);
      const connectionOpen = this.sock.connection === 'open';

      const connected = wsConnected && userLogged && connectionOpen;
      
      if (!connected) {
        logger.debug('Connection check failed', {
          wsConnected,
          userLogged,
          connectionOpen,
          connection: this.sock.connection,
          wsState: this.sock.ws?.readyState
        });
      }

      return connected;
    } catch (err) {
      logger.error('Error in connection check', { error: err.message });
      return false;
    }
  }

  getConnectionStatus() {
    if (!this.sock) return 'No socket instance';
    
    const wsStates = ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'];
    const wsState = wsStates[this.sock.ws?.readyState] || 'UNKNOWN';
    
    return `WS: ${wsState}, Connection: ${this.sock.connection}, User: ${this.sock.user?.id ? 'logged' : 'not-logged'}`;
  }

  async add(message) {
    if (this.queue.length >= CONFIG.MAX_QUEUE_SIZE) {
      throw new Error(`Queue penuh. Maksimal ${CONFIG.MAX_QUEUE_SIZE} pesan.`);
    }

    const messageId = crypto.randomUUID();
    const queueItem = {
      id: messageId,
      ...message,
      attempts: 0,
      addedAt: Date.now(),
      status: 'queued',
      lastAttempt: null
    };
    
    this.queue.push(queueItem);
    this.metrics.totalAdded++;
    
    logger.queue(`Pesan ditambahkan ke antrian`, { 
      id: messageId, 
      to: message.to,
      queueLength: this.queue.length 
    });
    
    // Start processing if not already running and not paused
    if (!this.processing && !this.processingPaused) {
      this.processQueue();
    }
    
    return messageId;
  }

  async processQueue() {
    if (this.processing || this.queue.length === 0 || this.processingPaused) {
      return;
    }

    this.processing = true;
    logger.queue('Memulai pemrosesan antrian', { 
      queueLength: this.queue.length,
      paused: this.processingPaused 
    });

    while (this.queue.length > 0 && !this.processingPaused) {
      const message = this.queue[0];
      
      try {
        // Update message status
        message.status = 'processing';
        message.attempts++;
        message.lastAttempt = Date.now();

        logger.queue(`Memproses pesan dari antrian`, { 
          id: message.id, 
          to: message.to,
          attempts: message.attempts,
          queuePosition: 0
        });

        // Wait for connection if not ready
        if (!this.isConnected()) {
          logger.warn('Koneksi WhatsApp tidak tersedia, menunggu...', {
            id: message.id,
            status: this.getConnectionStatus()
          });
          
          await this.sleep(3000);
          continue; // Skip this message for now
        }

        // Send the message
        await this.sendMessage(message);
        
        // Remove from queue after successful send
        this.queue.shift();
        this.metrics.sent++;
        
        logger.success(`Pesan berhasil dikirim ke ${message.to}`, { 
          id: message.id,
          attempts: message.attempts,
          queueLength: this.queue.length
        });

        // Small delay between messages to avoid rate limiting
        await this.sleep(1000);

      } catch (error) {
        logger.error(`Gagal mengirim pesan`, { 
          id: message.id,
          to: message.to,
          attempts: message.attempts,
          error: error.message
        });

        // Handle retry logic
        if (message.attempts < CONFIG.MESSAGE_RETRY_ATTEMPTS) {
          this.metrics.retried++;
          message.status = 'retrying';
          message.retryAfter = Date.now() + CONFIG.MESSAGE_RETRY_DELAY_MS;
          
          logger.queue(`Akan mencoba lagi pesan`, { 
            id: message.id,
            nextAttempt: message.attempts + 1,
            delay: CONFIG.MESSAGE_RETRY_DELAY_MS
          });

          // Move to end of queue for retry
          this.queue.shift();
          this.queue.push(message);
          
          await this.sleep(CONFIG.MESSAGE_RETRY_DELAY_MS);
        } else {
          // Max retries exceeded, remove from queue
          this.queue.shift();
          this.metrics.failed++;
          
          logger.error(`Pesan gagal setelah ${message.attempts} percobaan`, { 
            id: message.id,
            to: message.to
          });
        }
      }
    }

    this.processing = false;
    logger.queue('Pemrosesan antrian selesai', { 
      queueLength: this.queue.length 
    });
  }

  async sendMessage(message) {
    const jid = this.normalizeJid(message.to);
    
    logger.debug(`Mengirim pesan ke ${jid}`, { 
      id: message.id,
      messageLength: message.message?.length
    });

    try {
      // Validate connection again before sending
      if (!this.isConnected()) {
        throw new Error(`WhatsApp tidak terhubung. Status: ${this.getConnectionStatus()}`);
      }

      // Send message with timeout
      const sendPromise = this.sock.sendMessage(jid, { text: message.message });
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Timeout pengiriman pesan')), CONFIG.MESSAGE_TIMEOUT_MS);
      });

      await Promise.race([sendPromise, timeoutPromise]);
      
      logger.debug('Pesan berhasil dikirim', { id: message.id });

    } catch (error) {
      logger.error('Error dalam pengiriman pesan', { 
        id: message.id, 
        error: error.message,
        connectionStatus: this.getConnectionStatus()
      });
      throw error;
    }
  }

  normalizeJid(phone) {
    let cleaned = phone.replace(/\D/g, '');
    
    // Remove leading zeros
    if (cleaned.startsWith('0')) {
      cleaned = cleaned.substring(1);
    }
    
    // Add country code if missing (assuming Indonesia +62)
    if (!cleaned.startsWith('62') && cleaned.length >= 9) {
      cleaned = '62' + cleaned;
    }
    
    // Validate final format
    if (!/^62\d{9,12}$/.test(cleaned)) {
      throw new Error(`Nomor telepon tidak valid: ${phone} -> ${cleaned}`);
    }
    
    return `${cleaned}@s.whatsapp.net`;
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  pauseProcessing() {
    this.processingPaused = true;
    logger.queue('Pemrosesan antrian dijeda');
  }

  resumeProcessing() {
    this.processingPaused = false;
    logger.queue('Pemrosesan antrian dilanjutkan');
    if (this.queue.length > 0 && !this.processing) {
      this.processQueue();
    }
  }

  clearQueue() {
    const clearedCount = this.queue.length;
    this.queue = [];
    logger.queue(`Antrian dibersihkan`, { clearedCount });
    return clearedCount;
  }

  getQueueStatus() {
    return {
      queue: this.queue.map(msg => ({
        id: msg.id,
        to: msg.to,
        attempts: msg.attempts,
        status: msg.status,
        addedAt: new Date(msg.addedAt).toISOString(),
        age: Date.now() - msg.addedAt
      })),
      metrics: this.getMetrics(),
      processing: this.processing,
      paused: this.processingPaused,
      connectionStatus: this.getConnectionStatus()
    };
  }

  getMetrics() {
    return {
      ...this.metrics,
      queueLength: this.queue.length,
      processing: this.processing,
      paused: this.processingPaused,
      connected: this.isConnected()
    };
  }
}

const messageQueue = new FixedMessageQueue();

// ========== FIXED WHATSAPP CONNECTION ==========
let sock = null;
let qrBase64 = null;
let isConnecting = false;

const connectionState = {
  connected: false,
  lastConnected: null,
  reconnectAttempts: 0,
  totalMessages: 0,
  errors: 0,
  connectionStatus: 'disconnected'
};

async function clearAuthFolder() {
  const folder = path.join(__dirname, 'auth');
  try {
    await fs.rm(folder, { recursive: true, force: true });
    logger.info('Folder auth dibersihkan');
  } catch (err) {
    logger.error('Gagal menghapus folder auth', { error: err.message });
  }
}

async function startWhatsAppConnection() {
  if (isConnecting) {
    logger.connection('Koneksi WhatsApp sedang berjalan, skip...');
    return;
  }

  isConnecting = true;
  
  try {
    logger.connection('Memulai koneksi WhatsApp...');

    // Clear previous connection
    if (sock) {
      try {
        sock.ws?.close();
        sock.end?.();
      } catch (err) {
        // Ignore cleanup errors
      }
      sock = null;
    }

    const { state, saveCreds } = await useMultiFileAuthState('auth');
    const { version } = await fetchLatestBaileysVersion();

    // Configure socket dengan options yang lebih robust
    sock = makeWASocket({
      version,
      auth: state,
      printQRInTerminal: true,
      browser: Browsers.ubuntu('Chrome'), // Add browser info
      markOnlineOnConnect: true,
      generateHighQualityLinkPreview: true,
      emitOwnEvents: true,
      // Connection settings
      defaultQueryTimeoutMs: 60000,
      keepAliveIntervalMs: 10000,
      connectTimeoutMs: 30000,
      // Retry settings
      maxRetries: 10,
      retryRequestDelayMs: 250,
      // Optimize for stability
      fireInitQueries: true,
      syncFullHistory: false,
      transactionOpts: {
        maxCommitRetries: 3,
        delayBetweenTriesMs: 1000
      }
    });

    // Set socket to message queue
    messageQueue.setSocket(sock);

    logger.connection('Socket WhatsApp berhasil dibuat');

    // Setup event handlers
    setupEventHandlers(sock, saveCreds);

    // Start connection monitoring
    startConnectionMonitoring();

  } catch (error) {
    logger.error('Gagal membuat koneksi WhatsApp', { 
      error: error.message,
      stack: error.stack 
    });
    isConnecting = false;
    
    // Retry dengan exponential backoff
    const delayTime = Math.min(5000 * (connectionState.reconnectAttempts + 1), 60000);
    logger.connection(`Akan mencoba lagi dalam ${delayTime}ms`);
    setTimeout(startWhatsAppConnection, delayTime);
  }
}

function setupEventHandlers(sock, saveCreds) {
  // Connection update handler
  sock.ev.on('connection.update', async (update) => {
    const { connection, qr, lastDisconnect } = update;

    logger.connection('Update koneksi WhatsApp', {
      connection,
      hasQR: !!qr,
      lastDisconnect: lastDisconnect?.error?.message,
      qrLength: qr?.length
    });

    // Handle QR Code
    if (qr) {
      try {
        qrBase64 = await qrcode.toDataURL(qr);
        logger.connection('QR Code generated - Silakan scan');
        
        // Auto-clear QR after 30 seconds
        setTimeout(() => {
          if (connection !== 'open') {
            qrBase64 = null;
            logger.connection('QR Code expired');
          }
        }, 30000);
      } catch (error) {
        logger.error('Gagal generate QR code', { error: error.message });
      }
    }

    // Handle connection open
    if (connection === 'open') {
      isConnecting = false;
      connectionState.connected = true;
      connectionState.lastConnected = new Date();
      connectionState.reconnectAttempts = 0;
      connectionState.connectionStatus = 'connected';

      logger.success('WhatsApp berhasil terhubung!', {
        user: sock.user?.id,
        name: sock.user?.name,
        platform: sock.user?.platform
      });

      // Clear QR code
      qrBase64 = null;

      // Resume queue processing
      messageQueue.resumeProcessing();

      // Send welcome message to indicate connection is ready
      try {
        if (sock.user?.id) {
          await sock.sendMessage(sock.user.id, { 
            text: '🤖 WhatsApp Gateway telah terhubung dan siap digunakan!' 
          });
        }
      } catch (error) {
        // Ignore errors in welcome message
      }
    }

    // Handle connection close
    if (connection === 'close') {
      isConnecting = false;
      connectionState.connected = false;
      connectionState.connectionStatus = 'disconnected';
      connectionState.reconnectAttempts++;

      const statusCode = lastDisconnect?.error?.output?.statusCode;
      const reason = lastDisconnect?.error?.message || 'Unknown reason';

      logger.warn('Koneksi WhatsApp terputus', {
        statusCode,
        reason,
        reconnectAttempt: connectionState.reconnectAttempts
      });

      // Pause queue processing
      messageQueue.pauseProcessing();

      // Handle different disconnect scenarios
      if (statusCode === DisconnectReason.loggedOut) {
        logger.connection('Logged out dari WhatsApp, membersihkan auth...');
        await clearAuthFolder();
        setTimeout(startWhatsAppConnection, 3000);
      } else if (statusCode === DisconnectReason.restartRequired) {
        logger.connection('Restart required, menghubungkan kembali...');
        setTimeout(startWhatsAppConnection, 5000);
      } else if (statusCode === DisconnectReason.badSession) {
        logger.connection('Session rusak, membersihkan dan menghubungkan kembali...');
        await clearAuthFolder();
        setTimeout(startWhatsAppConnection, 5000);
      } else {
        // Exponential backoff untuk koneksi ulang
        const delay = Math.min(1000 * Math.pow(2, connectionState.reconnectAttempts), 30000);
        logger.connection(`Akan mencoba reconnect dalam ${delay}ms`);
        setTimeout(startWhatsAppConnection, delay);
      }
    }

    // Handle connecting state
    if (connection === 'connecting') {
      connectionState.connectionStatus = 'connecting';
      logger.connection('Menghubungkan ke WhatsApp...');
      messageQueue.pauseProcessing();
    }
  });

  // Credentials update handler
  sock.ev.on('creds.update', saveCreds);

  // Messages handler
  sock.ev.on('messages.upsert', async ({ messages, type }) => {
    if (type !== 'notify') return;

    const message = messages[0];
    if (!message.message || message.key.fromMe) return;

    connectionState.totalMessages++;

    const from = message.key.remoteJid;
    const messageText = message.message.conversation || 
                       message.message.extendedTextMessage?.text || 
                       '[Media/Other Message]';

    logger.message(`Pesan masuk dari ${from}`, {
      preview: messageText.substring(0, 100),
      messageTimestamp: message.messageTimestamp
    });

    // Kirim ke webhook Laravel jika ada
    if (CONFIG.LARAVEL_WEBHOOK_URL) {
      try {
        await axios.post(CONFIG.LARAVEL_WEBHOOK_URL, {
          from,
          message: messageText,
          timestamp: new Date().toISOString(),
          messageId: message.key.id
        }, {
          headers: {
            'Authorization': `Bearer ${CONFIG.LARAVEL_API_KEY}`,
            'Content-Type': 'application/json'
          },
          timeout: 5000
        });
      } catch (error) {
        logger.error('Gagal mengirim webhook', { error: error.message });
      }
    }
  });

  // Connection ready handler
  sock.ev.on('connection.ready', () => {
    logger.connection('Koneksi WhatsApp ready');
  });
}

function startConnectionMonitoring() {
  setInterval(() => {
    if (sock) {
      const wsState = sock.ws?.readyState;
      const shouldBeConnected = connectionState.connected;
      
      // Detect connection inconsistencies
      if (shouldBeConnected && wsState !== 1) {
        logger.error('Inkonsistensi koneksi terdeteksi', {
          baileysConnected: connectionState.connected,
          wsState: wsState,
          connection: sock.connection
        });
        
        // Force reconnection
        connectionState.connected = false;
        messageQueue.pauseProcessing();
        startWhatsAppConnection();
      }
    }
  }, 10000); // Check every 10 seconds
}

// ========== EXPRESS APP & ROUTES ==========
const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: CONFIG.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { status: false, message: 'Terlalu banyak request' }
});

const messageLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { status: false, message: 'Terlalu banyak pesan' }
});

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.headers.authorization;
  if (!token || token !== `Bearer ${CONFIG.LARAVEL_API_KEY}`) {
    return res.status(401).json({ status: false, message: 'Unauthorized' });
  }
  next();
}

// ========== FIXED ROUTES ==========

// Health check dengan status koneksi lengkap
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    connection: {
      connected: connectionState.connected,
      status: connectionState.connectionStatus,
      lastConnected: connectionState.lastConnected,
      reconnectAttempts: connectionState.reconnectAttempts,
      detailedStatus: messageQueue.getConnectionStatus(),
      hasSocket: !!sock,
      hasUser: !!sock?.user?.id,
      userInfo: sock?.user ? {
        id: sock.user.id,
        name: sock.user.name,
        platform: sock.user.platform
      } : null
    },
    queue: messageQueue.getMetrics(),
    memory: {
      used: `${(process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2)} MB`,
      total: `${(process.memoryUsage().heapTotal / 1024 / 1024).toFixed(2)} MB`
    },
    uptime: `${Math.floor(process.uptime())} seconds`
  });
});

// Send message endpoint
app.post('/send-message', messageLimiter, async (req, res) => {
  const { to, message } = req.body;

  if (!to || !message) {
    return res.status(400).json({ 
      status: false, 
      message: 'Parameter to dan message wajib diisi' 
    });
  }

  // Validasi nomor telepon
  const phoneRegex = /^(\+62|62|0)8[1-9][0-9]{6,9}$/;
  if (!phoneRegex.test(to.replace('@s.whatsapp.net', ''))) {
    return res.status(400).json({ 
      status: false, 
      message: 'Format nomor telepon tidak valid' 
    });
  }

  try {
    // Check connection status
    if (!messageQueue.isConnected()) {
      return res.status(503).json({ 
        status: false, 
        message: 'WhatsApp tidak terhubung. Silakan scan QR code terlebih dahulu.',
        connectionStatus: messageQueue.getConnectionStatus(),
        qrAvailable: !!qrBase64
      });
    }

    const messageId = await messageQueue.add({
      to: to.replace('@s.whatsapp.net', ''),
      message: message.substring(0, 10000) // Limit message length
    });

    res.json({ 
      status: true, 
      message: 'Pesan berhasil ditambahkan ke antrian',
      messageId,
      queueLength: messageQueue.queue.length,
      estimatedWait: Math.max(messageQueue.queue.length * 2, 5) // Minimum 5 seconds
    });

  } catch (error) {
    logger.error('Gagal menambahkan pesan ke antrian', { error: error.message });
    res.status(500).json({ 
      status: false, 
      message: 'Gagal menambahkan pesan ke antrian',
      error: error.message 
    });
  }
});

// QR Code endpoint
app.get('/qr', (req, res) => {
  if (qrBase64) {
    res.json({ 
      status: true, 
      qr: qrBase64,
      message: 'Scan QR code ini dengan WhatsApp'
    });
  } else if (connectionState.connected) {
    res.json({ 
      status: true, 
      qr: null,
      message: 'WhatsApp sudah terhubung',
      user: sock.user?.id 
    });
  } else {
    res.json({ 
      status: false, 
      qr: null,
      message: 'QR code tidak tersedia. Menghubungkan...' 
    });
  }
});

// Queue management endpoints
app.get('/queue/status', (req, res) => {
  res.json({
    status: true,
    ...messageQueue.getQueueStatus()
  });
});

app.post('/queue/clear', (req, res) => {
  const cleared = messageQueue.clearQueue();
  res.json({
    status: true,
    message: `Berhasil menghapus ${cleared} pesan dari antrian`,
    clearedCount: cleared
  });
});

// Connection management
app.post('/connection/restart', async (req, res) => {
  try {
    logger.warn('Restart koneksi diminta via API');
    
    // Reset state
    connectionState.connected = false;
    connectionState.connectionStatus = 'restarting';
    messageQueue.pauseProcessing();
    
    // Clear auth and restart
    await clearAuthFolder();
    
    res.json({ 
      status: true, 
      message: 'Koneksi WhatsApp sedang direstart...' 
    });
    
    // Start new connection
    setTimeout(startWhatsAppConnection, 2000);
    
  } catch (error) {
    logger.error('Gagal restart koneksi', { error: error.message });
    res.status(500).json({ 
      status: false, 
      message: 'Gagal restart koneksi' 
    });
  }
});

// ========== STARTUP ==========
async function startServer() {
  try {
    // Start WhatsApp connection first
    await startWhatsAppConnection();
    
    // Start HTTP server
    app.listen(CONFIG.PORT, () => {
      const localIp = getLocalIp();
      console.log(`
╔═══════════════════════════════════════════════════╗
║                                                   ║
║  🚀 WhatsApp Gateway - FIXED CONNECTION          ║
║                                                   ║
║  Server: http://localhost:${CONFIG.PORT}                ║
║          http://${localIp}:${CONFIG.PORT}                ║
║                                                   ║
║  Status: ✅ Running                              ║
║                                                   ║
╚═══════════════════════════════════════════════════╝
      `);
      
      logger.success('Server berhasil dijalankan', {
        port: CONFIG.PORT,
        localIp: localIp
      });
    });
    
  } catch (error) {
    logger.error('Gagal start server', { error: error.message });
    process.exit(1);
  }
}

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

// Process handlers
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

async function gracefulShutdown() {
  logger.warn('Shutdown signal received');
  
  messageQueue.pauseProcessing();
  
  if (sock) {
    try {
      await sock.logout();
      logger.info('WhatsApp logged out');
    } catch (error) {
      logger.error('Error logging out WhatsApp', { error: error.message });
    }
  }
  
  process.exit(0);
}

// Start the application
startServer();