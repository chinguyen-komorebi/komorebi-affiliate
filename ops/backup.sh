#!/bin/bash
set -e

source /root/komorebi-affiliate/.env

notify(){ curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" -d chat_id=$TELEGRAM_CHAT_ID -d text="$1" >/dev/null; }
trap 'notify "❌ Backup FAILED (exit $?) at line $LINENO — affiliate_$(date +%Y%m%d) on komorebi server"' ERR

DATE=$(date +%Y%m%d)
DB=/root/komorebi-affiliate/affiliate.db
BACKUP=/tmp/affiliate_${DATE}.db
ENCRYPTED=/tmp/affiliate_${DATE}.db.gpg

cp $DB $BACKUP

echo $BACKUP_PASSPHRASE | gpg --batch --yes --passphrase-fd 0 \
  --symmetric --cipher-algo AES256 -o $ENCRYPTED $BACKUP

s3cmd --access_key=$DO_SPACES_KEY --secret_key=$DO_SPACES_SECRET \
  --host=sgp1.digitaloceanspaces.com \
  --host-bucket=komorebi-backups.sgp1.digitaloceanspaces.com \
  put $ENCRYPTED s3://komorebi-backups/affiliate_${DATE}.db.gpg

rm -f $BACKUP $ENCRYPTED

curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
  -d chat_id=$TELEGRAM_CHAT_ID \
  -d text="✅ Backup done: affiliate_${DATE}.db.gpg → komorebi-backups"

echo "Backup completed: $DATE"
