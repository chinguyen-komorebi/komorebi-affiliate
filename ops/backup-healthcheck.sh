#!/bin/bash
source /root/komorebi-affiliate/.env

THRESHOLD_HOURS=26
NOW=$(date +%s)

LATEST=$(s3cmd --access_key=$DO_SPACES_KEY --secret_key=$DO_SPACES_SECRET \
  --host=sgp1.digitaloceanspaces.com \
  --host-bucket=komorebi-backups.sgp1.digitaloceanspaces.com \
  ls s3://komorebi-backups/ \
  | sort | tail -1)

if [ -z "$LATEST" ]; then
  curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d chat_id=$TELEGRAM_CHAT_ID \
    -d text="❌ Backup health-check: KHÔNG tìm thấy file backup nào trên Spaces — kiểm tra ngay!" \
    >/dev/null
  exit 1
fi

FILE_DATE=$(echo "$LATEST" | awk '{print $1, $2}')
FILE_TS=$(date -d "$FILE_DATE" +%s 2>/dev/null || date -j -f "%Y-%m-%d %H:%M" "$FILE_DATE" +%s)
AGE_HOURS=$(( (NOW - FILE_TS) / 3600 ))

if [ "$AGE_HOURS" -gt "$THRESHOLD_HOURS" ]; then
  FILE_NAME=$(echo "$LATEST" | awk '{print $4}')
  curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d chat_id=$TELEGRAM_CHAT_ID \
    -d text="⚠️ Backup health-check: file mới nhất (${FILE_NAME##*/}) đã ${AGE_HOURS}h tuổi — backup có thể không chạy!" \
    >/dev/null
  exit 1
fi

echo "Backup health-check OK: latest backup ${AGE_HOURS}h ago"
