#!/bin/bash
source /root/komorebi-affiliate/.env

notify(){ curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
  -d chat_id=$TELEGRAM_CHAT_ID -d text="$1" >/dev/null; }

HEALTH=$(curl -s https://track.komorebimedia.com/health)
STATUS=$(echo $HEALTH | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['status'])" 2>/dev/null)
PM2_STATUS=$(pm2 jlist 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['pm2_env']['status'])" 2>/dev/null)
DB_SIZE=$(du -sh /root/komorebi-affiliate/affiliate.db 2>/dev/null | cut -f1)
UPTIME=$(uptime -p)

if [ "$STATUS" = "ok" ] && [ "$PM2_STATUS" = "online" ]; then
  notify "✅ Platform daily check OK
- Health: $STATUS
- PM2: $PM2_STATUS
- DB size: $DB_SIZE
- Server: $UPTIME"
else
  notify "❌ Platform daily check FAILED
- Health: $STATUS
- PM2: $PM2_STATUS
- DB size: $DB_SIZE
- Server: $UPTIME"
fi

echo "Verify completed: $(date)"
