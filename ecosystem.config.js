'use strict';

// PM2 ecosystem config — run as a non-root user in production.
//
// SETUP ON SERVER (one-time):
//   sudo useradd --system --no-create-home --shell /usr/sbin/nologin komorebi
//   sudo mkdir -p /opt/komorebi-affiliate
//   sudo chown komorebi:komorebi /opt/komorebi-affiliate
//   sudo -u komorebi cp -r . /opt/komorebi-affiliate/
//   sudo -u komorebi npm ci --omit=dev
//
// START (as that user via pm2):
//   sudo -u komorebi pm2 start ecosystem.config.js --env production
//   sudo -u komorebi pm2 save
//   sudo pm2 startup   # follow the printed command to auto-start on boot
//
// The app must not bind to port 80/443 directly (privileged ports).
// Use a reverse proxy (nginx/caddy) listening on 443 → forward to PORT below.

module.exports = {
  apps: [
    {
      name:          'komorebi-affiliate',
      script:        './server.js',
      instances:     1,
      autorestart:   true,
      watch:         false,
      max_memory_restart: '512M',
      env: {
        NODE_ENV: 'development',
        PORT:     3000,
      },
      env_production: {
        NODE_ENV: 'production',
        PORT:     3000,
      },
    },
  ],
};
