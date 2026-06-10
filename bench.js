'use strict';
/*
 * bench.js — single-core throughput benchmark for the tracker's hot path.
 *
 * The Komorebi tracker is a single Node process with SYNCHRONOUS node:sqlite
 * writes, so click ingest throughput is bound by how fast ONE core can run:
 *   crypto.randomUUID()  +  a 30-column INSERT into a WAL SQLite table.
 * This reproduces exactly that, with no app/server/network/deps involved, so it
 * can run anywhere Node 22+ is installed (incl. the prod box) to get a clean
 * hardware ratio. It writes only a temp DB in os.tmpdir() and deletes it.
 *
 * Run:  node bench.js
 * Compare the "inserts/sec" line across machines:
 *   ratio = faster_ips / slower_ips ;  prod_capacity ≈ local_capacity / ratio
 */

const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

const DUR_MS = 4000;     // time-bounded so it takes ~4s on any hardware
const WARMUP = 20000;

const dbPath = path.join(os.tmpdir(), `bench_${process.pid}.db`);
for (const f of [dbPath, dbPath + '-wal', dbPath + '-shm']) { try { fs.unlinkSync(f); } catch {} }

const db = new DatabaseSync(dbPath);
db.exec('PRAGMA journal_mode = WAL');          // mirror db.js
db.exec('PRAGMA foreign_keys = ON');
db.exec(`CREATE TABLE clicks (
  click_id TEXT, advertiser_slug TEXT, publisher TEXT, ip TEXT, user_agent TEXT, country TEXT,
  device_type TEXT, os TEXT, browser TEXT, sub1 TEXT, sub2 TEXT, sub3 TEXT, sub4 TEXT, sub5 TEXT,
  subpub TEXT, gclid TEXT, fbclid TEXT, referrer TEXT, af_siteid TEXT, af_campaign TEXT, af_adset TEXT,
  af_ad TEXT, adjust_network TEXT, adjust_campaign TEXT, adjust_adgroup TEXT, adjust_creative TEXT,
  campaign TEXT, adgroup TEXT, creative TEXT, network TEXT)`);

const stmt = db.prepare(`INSERT INTO clicks (click_id, advertiser_slug, publisher, ip, user_agent, country,
  device_type, os, browser, sub1, sub2, sub3, sub4, sub5, subpub, gclid, fbclid, referrer,
  af_siteid, af_campaign, af_adset, af_ad, adjust_network, adjust_campaign, adjust_adgroup, adjust_creative,
  campaign, adgroup, creative, network)
  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);

// one representative click row (mix of values + nulls, like a real /track hit)
function insertOne() {
  const clickId = crypto.randomUUID();
  stmt.run(clickId, 'loadtest-game', 'loadpub01', '203.0.113.45',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
    'VN', 'mobile', 'iOS', 'Safari',
    'campA', null, null, null, null, 'aff9', null, null, 'https://ref.example.com/x',
    'site42', 'AFc', null, 'AFcr', null, null, null, null,
    'AFc', null, 'AFcr', 'site42');
}

for (let i = 0; i < WARMUP; i++) insertOne();

let n = 0;
const t0 = process.hrtime.bigint();
const deadline = t0 + BigInt(DUR_MS) * 1000000n;
while (process.hrtime.bigint() < deadline) {
  // batch the clock check so timing overhead doesn't dominate
  for (let i = 0; i < 1000; i++) insertOne();
  n += 1000;
}
const secs = Number(process.hrtime.bigint() - t0) / 1e9;
db.close();
for (const f of [dbPath, dbPath + '-wal', dbPath + '-shm']) { try { fs.unlinkSync(f); } catch {} }

const ips = Math.round(n / secs);
const cpus = os.cpus();
console.log('--- tracker hot-path single-core benchmark ---');
console.log(`node:        ${process.version}  (${process.platform}/${process.arch})`);
console.log(`cpu:         ${cpus[0] ? cpus[0].model : 'unknown'}  x${cpus.length} logical`);
console.log(`inserts:     ${n.toLocaleString()} in ${secs.toFixed(2)}s`);
console.log(`inserts/sec: ${ips.toLocaleString()}   <-- compare this number across machines`);
