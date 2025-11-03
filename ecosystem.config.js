module.exports = {
  apps: [{
    name: 'wa-gateway',
    script: './index.js',
    instances: 1,
    exec_mode: 'fork',
    max_restarts: 10, // ✅ Maksimal 10 restart
    min_uptime: '10s', // ✅ Minimal uptime 10 detik
    max_memory_restart: '500M',
    error_file: './logs/pm2-error.log',
    out_file: './logs/pm2-out.log',
    time: true,
    autorestart: true,
    watch: false,
    exp_backoff_restart_delay: 100 // ✅ Exponential backoff
  }]
};