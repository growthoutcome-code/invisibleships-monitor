# Site Integrity Monitor — invisibleships.com (reusable)

A tamper-evident change monitor for web properties. It answers two questions on a
minute-to-minute basis: **did anything change**, and **did that change come
through the normal Git → Vercel pipeline or bypass it** (the fingerprint of a
hidden/anomalous change).

## Files
- `site_monitor.py` — the runner (one pass = fetch + hash + diff + correlate + log + alert).
- `site_baseline.invisibleships.json` — Git-derived fingerprint of the intended
  static resources (`/corpus/*.json`) for the current production deployment.
  Regenerate this whenever you intentionally deploy new corpus content.
- `monitor-state/<property>/evidence_log.jsonl` — the append-only, hash-chained
  evidence log. `monitor-state/<property>/snapshots/` — full raw captures saved
  whenever content changes.

## What each run does
1. Fetches the configured pages + resources from the LIVE site.
2. Hashes each response (sha256; pages also get a whitespace-normalized text hash).
3. Compares resources to the **Git baseline** (integrity) and everything to the
   **previous run** (change detection).
4. Asks the Vercel API for the current production deployment. A content change
   **with no new deployment** is flagged `changed_without_deploy` — that's the
   signal to go look at Supabase logs for the same time window.
5. Appends a hash-chained entry to the evidence log and, on any change/anomaly,
   emails + texts you.

## Run it every minute (always-on host)
This must run somewhere always-on — a small VPS, a home server, or a scheduler.
An ephemeral session can't be a 24/7 watchdog.

```bash
# one-time
export MONITOR_STATE_DIR=/var/monitor-state
export VERCEL_TOKEN=...            # read-only Vercel token (for deploy correlation)
# email alerts
export SMTP_HOST=smtp.gmail.com SMTP_PORT=587
export SMTP_USER=you@gmail.com SMTP_PASS='app-password'
export ALERT_FROM=you@gmail.com ALERT_TO=growthoutcome@gmail.com
# text alerts (simplest: your carrier's email-to-SMS gateway, e.g. 5551234567@vtext.com)
export ALERT_SMS=5551234567@vtext.com

# cron: every minute
* * * * * cd /opt/monitor && /usr/bin/python3 site_monitor.py >> /var/log/monitor.log 2>&1
```

Verify the log hasn't been tampered with at any time:
```bash
python3 -c "import site_monitor as s; print(s.verify_chain('monitor-state/invisibleships.com/evidence_log.jsonl'))"
```

## Alerts
- **Email**: set the `SMTP_*` / `ALERT_TO` vars. A Gmail App Password works.
- **SMS**: cheapest is your carrier's email-to-SMS gateway address in `ALERT_SMS`
  (Verizon `@vtext.com`, AT&T `@txt.att.net`, T-Mobile `@tmomail.net`). For a
  reliable dedicated gateway use Twilio and wire a `send_sms_twilio()` (stub noted
  in the code). Sensitivity is set to **any content change** per your request.

## Reuse across properties
Add another object to `CONFIG["properties"]` (name, `base_url`, `pages`,
`resources`/baseline, optional `vercel`, `gate_marker`). One process covers all.

## Attribution & the IP question — read this
- Scraping the site tells you **what** changed, not **who**. The page only shows
  the result. **Real IP capture lives at the source**: Supabase request logs and
  Vercel Log Drains record client IPs; the site scrape does not.
- For site *content*, the best "who" is usually the **Git commit author / Vercel
  account** that deployed — a raw actor IP needs paid Vercel/GitHub audit logs.
- **VPN caveat (both directions):**
  - *Your own VPN* — record your VPN exit IP(s) as known-good so your legitimate
    actions aren't flagged as the anomaly. A rotating/shared consumer VPN makes
    this hard; a dedicated static IP for admin work makes the log much cleaner.
  - *Someone else's VPN/Tor* — the captured IP is a shared exit node, often
    reassigned and no-logs. Treat an IP as **corroborating** evidence (timestamp
    and pattern correlation, which credential/role was used), not identification.
    Resolving it to a person generally needs legal process the provider may not
    honor.

## Evidence integrity / chain of custody
- The log is append-only and hash-chained (each entry embeds the prior entry's
  hash), so any later edit or deletion is detectable via `verify_chain`.
- Keep the runner's clock NTP-synced; timestamps are UTC.
- Store this log **off** the monitored systems (not on Vercel/Supabase) so a
  compromise of those can't alter the evidence. Back it up append-only.
- If this may become a formal investigation, preserve raw snapshots and involve
  counsel/forensics before relying on it — IP evidence has the limits above.

## The other half (in progress)
This covers the public site. The higher-value forensic layer is **Supabase audit
triggers + request-IP logging**, which records every INSERT/UPDATE/DELETE (old
value, new value, role, timestamp) at the source — catching "hidden
contributions" the site scrape can only infer. That migration is being prepared
separately.
