# GitHub setup — Invisible Ships site integrity monitor

This turns the monitor into a 24/7 job on GitHub Actions with a persistent,
hash-chained evidence log. ~10 minutes, and (as configured) $0.

## 1. Create the repo
- New GitHub repo, **Private**, e.g. `invisibleships-monitor`.
  - Private keeps the evidence log non-public.
  - The default 30-minute cadence stays within the free Actions tier on a
    private repo (~1,440 of the 2,000 free minutes/month).

## 2. Put this bundle in the repo (root)
Upload everything in this folder to the repo root, keeping structure:
```
site_monitor.py
site_baseline.invisibleships.json
README.md
GITHUB_SETUP.md
.gitignore
.github/workflows/monitor.yml
monitor-state/invisibleships.com/evidence_log.jsonl   (seeded baseline)
```
Easiest: GitHub web → **Add file → Upload files** → drag the folder in → Commit.
(Or push with git / GitHub Desktop.)

## 3. Add Actions secrets
Settings → **Secrets and variables → Actions** → **New repository secret**:

| Secret | Value | Notes |
|---|---|---|
| `VERCEL_TOKEN` | a read-only Vercel token | vercel.com → Account Settings → Tokens. Enables deploy-correlation. Optional. |
| `SMTP_HOST` | `smtp.gmail.com` | for email alerts |
| `SMTP_PORT` | `587` | |
| `SMTP_USER` | your gmail address | |
| `SMTP_PASS` | a Gmail **App Password** | myaccount.google.com → Security → App passwords |
| `ALERT_FROM` | your gmail address | |
| `ALERT_TO` | `growthoutcome@gmail.com` | where alerts go |
| `ALERT_SMS` | e.g. `5551234567@vtext.com` | your carrier's email-to-SMS gateway. Optional. |

If you skip the email secrets for now, the monitor still runs and logs — it
just won't send alerts until they're set.

## 4. Turn it on + test
- **Actions** tab → enable workflows if prompted → pick **site-monitor** →
  **Run workflow** (manual trigger).
- Confirm: the run is green, a new line was appended to the evidence log, and a
  `monitor run: …` commit appeared.

## 5. It now runs automatically every 30 minutes
- Change cadence by editing the `cron` line in `.github/workflows/monitor.yml`
  (GitHub minimum 5 min; tighter cadence on a private repo costs money — see
  README cost notes).
- **Verify the log hasn't been tampered with, anytime:**
  ```bash
  python3 -c "import site_monitor as s; print(s.verify_chain('monitor-state/invisibleships.com/evidence_log.jsonl'))"
  ```

## Maintenance
- Regenerate `site_baseline.invisibleships.json` whenever you INTENTIONALLY deploy
  new corpus content (otherwise legitimate updates show as anomalies).
- Keep an off-repo backup/mirror of the evidence log for chain-of-custody.
- A change flagged `changed_without_deploy` = content changed with no new Vercel
  deployment → go check the Supabase audit log for the same time window.
