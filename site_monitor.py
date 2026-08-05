#!/usr/bin/env python3
"""
site_monitor.py — tamper-evident change monitor for web properties.

DEFENSIVE ONLY. It READS the live site (like any visitor) and hashes it. It never
edits the site, the database, the repo content, or anything else. The only thing
it writes is its own append-only evidence log.

WHAT IT DOES (per run, per property)
  1. Fetches configured pages + static resources from the LIVE site.
  2. Hashes each response and compares to the Git-derived BASELINE (what SHOULD be
     served) and to the PREVIOUS run.
  3. Correlates with the current production deployment (Vercel API). A change with
     NO new deployment is an edit that did NOT come through Git/Vercel/Claude.
  4. Appends a hash-CHAINED entry to an append-only evidence log.
  5. When an OUTSIDE-pipeline edit is found (change/anomaly with no new deploy) it
     writes an evidence report + saves the raw served bytes, emails you (with the
     evidence attached), and exits code 2 so the GitHub Action fails and GitHub
     sends you its own failure email too.

EXIT CODES: 0 = clean, 2 = outside-pipeline edit detected, 1 = monitor error.
"""

import argparse, datetime, hashlib, json, os, smtplib, ssl, sys
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib import request as urlrequest, error as urlerror

# --------------------------------------------------------------------------- #
# CONFIG — edit here (or point MONITOR_CONFIG at a JSON file to override).
# --------------------------------------------------------------------------- #
CONFIG = {
    "state_dir": os.environ.get("MONITOR_STATE_DIR", "./monitor-state"),
    "user_agent": "InvisibleShips-Monitor/1.1 (+integrity-check)",
    "timeout_s": 20,
    "capture_headers": ["date", "age", "server", "x-vercel-id", "x-vercel-cache",
                        "x-matched-path", "content-type", "content-length",
                        "etag", "last-modified", "strict-transport-security"],
    "alerts": {
        "on": ["changed", "anomaly", "unreachable"],
        "email": {
            "enabled": bool(os.environ.get("SMTP_HOST")),
            "smtp_host": os.environ.get("SMTP_HOST", ""),
            "smtp_port": int(os.environ.get("SMTP_PORT", "587")),
            "username": os.environ.get("SMTP_USER", ""),
            "password": os.environ.get("SMTP_PASS", ""),
            "from_addr": os.environ.get("ALERT_FROM", ""),
            "to_addrs": [a for a in os.environ.get("ALERT_TO", "").split(",") if a],
        },
        "sms_to": [a for a in os.environ.get("ALERT_SMS", "").split(",") if a],
    },
    "properties": [
        {
            "name": "invisibleships.com",
            "base_url": "https://invisibleships.com",
            "pages": ["/", "/journal/is-j01-20250227-entry"],
            "resources": [],   # empty => check every resource in the baseline file
            "baseline_file": "site_baseline.invisibleships.json",
            "gate_marker": "18 or older",
            "vercel": {"project_id": "prj_WgklczuymEvBDnkaAFTCYljgQBkF",
                       "team": "growthoutcome", "token_env": "VERCEL_TOKEN"},
        },
    ],
}

# --------------------------------------------------------------------------- #
def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def sha256_bytes(b): return hashlib.sha256(b).hexdigest()

def normalize_text(b):
    try: t = b.decode("utf-8", "replace")
    except Exception: return sha256_bytes(b)
    return sha256_bytes(" ".join(t.split()).encode("utf-8"))

def canonical(obj): return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def load_config():
    p = os.environ.get("MONITOR_CONFIG")
    if p and os.path.exists(p): return json.load(open(p))
    return CONFIG

def fetch(url, cfg):
    req = urlrequest.Request(url, headers={"User-Agent": cfg["user_agent"]})
    try:
        with urlrequest.urlopen(req, timeout=cfg["timeout_s"]) as r:
            body = r.read()
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            return r.status, body, {k: hdrs.get(k) for k in cfg["capture_headers"] if k in hdrs}
    except urlerror.HTTPError as e:
        return e.code, (e.read() if hasattr(e, "read") else b""), {"error": f"HTTP {e.code}"}
    except Exception as e:
        return None, None, {"error": str(e)}

def vercel_current_prod(vc, cfg):
    tok = os.environ.get(vc.get("token_env", ""), "")
    if not tok: return None, None
    url = (f"https://api.vercel.com/v6/deployments?projectId={vc['project_id']}"
           f"&teamId={vc['team']}&target=production&state=READY&limit=1")
    req = urlrequest.Request(url, headers={"Authorization": f"Bearer {tok}"})
    try:
        with urlrequest.urlopen(req, timeout=cfg["timeout_s"]) as r:
            data = json.load(r)
        d = (data.get("deployments") or [None])[0]
        if not d: return None, None
        return d.get("uid") or d.get("id"), (d.get("meta") or {}).get("githubCommitSha")
    except Exception:
        return None, None

# --- evidence log (append-only, hash-chained) ------------------------------- #
def last_chain_hash(log_path):
    if not os.path.exists(log_path): return "GENESIS"
    last = "GENESIS"
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try: last = json.loads(line)["entry_hash"]
                except Exception: pass
    return last

def append_evidence(log_path, entry):
    entry = dict(entry)
    entry["prev_entry_hash"] = last_chain_hash(log_path)
    entry["entry_hash"] = sha256_bytes(canonical({k: entry[k] for k in entry if k != "entry_hash"}))
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
    with open(log_path, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry["entry_hash"]

def verify_chain(log_path):
    prev, n = "GENESIS", 0
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            e = json.loads(line); n += 1
            if e.get("prev_entry_hash") != prev: return False, n, e.get("seq")
            if sha256_bytes(canonical({k: e[k] for k in e if k != "entry_hash"})) != e.get("entry_hash"):
                return False, n, e.get("seq")
            prev = e["entry_hash"]
    return True, n, None

# --- alerting --------------------------------------------------------------- #
def send_email(cfg, subject, body, attachments=None):
    e = cfg["alerts"]["email"]
    if not e.get("enabled") or not e.get("to_addrs"):
        return "skipped(email not configured)"
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = e["from_addr"] or e["username"]
    msg["To"] = ", ".join(e["to_addrs"])
    msg.attach(MIMEText(body))
    for path in (attachments or []):
        try:
            with open(path, "rb") as fh:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(fh.read())
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f'attachment; filename="{os.path.basename(path)}"')
            msg.attach(part)
        except Exception:
            pass
    try:
        with smtplib.SMTP(e["smtp_host"], e["smtp_port"], timeout=20) as s:
            s.starttls(context=ssl.create_default_context())
            if e["username"]: s.login(e["username"], e["password"])
            s.sendmail(msg["From"], e["to_addrs"], msg.as_string())
        return "sent"
    except Exception as ex:
        return f"error({ex})"

def send_sms_via_email_gateway(cfg, body):
    sms_to = cfg["alerts"].get("sms_to") or []
    if not sms_to: return "skipped(no sms_to)"
    e = cfg["alerts"]["email"]
    if not e.get("enabled"): return "skipped(email transport needed for sms gateway)"
    msg = MIMEText(body[:300]); msg["Subject"] = "site alert"
    msg["From"] = e["from_addr"] or e["username"]; msg["To"] = ", ".join(sms_to)
    try:
        with smtplib.SMTP(e["smtp_host"], e["smtp_port"], timeout=20) as s:
            s.starttls(context=ssl.create_default_context())
            if e["username"]: s.login(e["username"], e["password"])
            s.sendmail(msg["From"], sms_to, msg.as_string())
        return "sent"
    except Exception as ex:
        return f"error({ex})"

# --- core pass -------------------------------------------------------------- #
def check_property(prop, cfg, script_dir):
    state_dir = os.path.join(cfg["state_dir"], prop["name"])
    snap_dir = os.path.join(state_dir, "snapshots")
    ev_dir = os.path.join(state_dir, "evidence")
    os.makedirs(snap_dir, exist_ok=True); os.makedirs(ev_dir, exist_ok=True)
    log_path = os.path.join(state_dir, "evidence_log.jsonl")
    prev_path = os.path.join(state_dir, "last_state.json")
    prev = json.load(open(prev_path)) if os.path.exists(prev_path) else {}

    baseline = {}
    bf = os.path.join(script_dir, prop.get("baseline_file", ""))
    if os.path.exists(bf):
        baseline = json.load(open(bf)).get("resources", {})

    vc = prop.get("vercel", {})
    dep_id, dep_sha = vercel_current_prod(vc, cfg) if vc else (None, None)
    prev_dep = prev.get("prod_deployment_id")
    new_deploy = bool(dep_id) and bool(prev_dep) and dep_id != prev_dep

    targets = list(prop.get("pages", [])) + (list(prop.get("resources") or baseline.keys()))
    observed, changes, anomalies, unreachable = {}, [], [], []
    ts = now_utc()

    for path in targets:
        url = prop["base_url"].rstrip("/") + path
        status, body, hdrs = fetch(url, cfg)
        is_page = path in prop.get("pages", [])
        rec = {"status": status, "headers": hdrs}
        if body is None:
            unreachable.append(path); rec["error"] = hdrs.get("error"); observed[path] = rec; continue
        rec["bytes"] = len(body); rec["sha256"] = sha256_bytes(body)
        rec["content_hash"] = normalize_text(body) if is_page else rec["sha256"]

        target_anoms = []
        if is_page and prop.get("gate_marker"):
            present = prop["gate_marker"].encode() in body
            rec["gate_present"] = present
            if not present: target_anoms.append({"path": path, "kind": "gate_marker_missing"})
        if not is_page and path in baseline:
            rec["matches_git_baseline"] = (rec["sha256"] == baseline[path]["sha256"])
            if not rec["matches_git_baseline"]:
                target_anoms.append({"path": path, "kind": "resource_differs_from_git",
                                     "expected_sha256": baseline[path]["sha256"], "got_sha256": rec["sha256"]})

        prev_rec = (prev.get("targets") or {}).get(path, {})
        changed = bool(prev_rec.get("content_hash")) and prev_rec["content_hash"] != rec["content_hash"]
        if changed:
            changes.append({"path": path, "kind": "content_changed",
                            "from": prev_rec["content_hash"], "to": rec["content_hash"],
                            "matched_new_deploy": new_deploy})
            if not new_deploy:
                target_anoms.append({"path": path, "kind": "changed_without_deploy"})

        # Save the exact served bytes as evidence whenever the target is noteworthy.
        if target_anoms or changed:
            snap_name = f"{(path.strip('/').replace('/', '_') or 'root')}.{ts.replace(':', '')}.{rec['sha256'][:12]}.bin"
            with open(os.path.join(snap_dir, snap_name), "wb") as fh:
                fh.write(body)
            rec["snapshot"] = snap_name
        anomalies.extend(target_anoms)
        observed[path] = rec

    # OUTSIDE the Git/Vercel/Claude pipeline = a change/anomaly with NO new deployment.
    outside = (not new_deploy) and bool(changes or anomalies) and dep_id is not None
    status_word = ("unreachable" if unreachable and len(unreachable) == len(targets)
                   else "anomaly" if anomalies else "changed" if changes else "ok")

    entry = {
        "seq": prev.get("seq", -1) + 1, "timestamp_utc": ts, "property": prop["name"],
        "status": status_word, "outside_pipeline_edit": outside,
        "prod_deployment_id": dep_id, "prod_git_sha": dep_sha,
        "new_deploy_since_last": new_deploy, "targets": observed,
        "changes": changes, "anomalies": anomalies, "unreachable": unreachable,
        "collector": {"host": os.uname().nodename, "tool": "site_monitor.py/1.1"},
    }
    entry_hash = append_evidence(log_path, entry)
    json.dump({"seq": entry["seq"], "prod_deployment_id": dep_id, "targets": observed},
              open(prev_path, "w"))

    # Build a focused evidence report + gather attachments when outside-pipeline.
    attachments = []
    if outside:
        snaps = [observed[p]["snapshot"] for p in observed if observed[p].get("snapshot")]
        report = {
            "alert": "UNINTENDED_EDIT_OUTSIDE_PIPELINE",
            "meaning": ("Content changed with NO corresponding Vercel deployment. Legitimate "
                        "changes go Git -> Vercel (that's how Claude/you deploy), so this edit "
                        "did not come through Git/Vercel/Claude."),
            "property": prop["name"], "timestamp_utc": ts,
            "production_deployment_id": dep_id, "production_git_sha": dep_sha,
            "note": "Production deployment is unchanged since the previous check — no deploy occurred.",
            "evidence_log": {"seq": entry["seq"], "entry_hash": entry_hash, "log": "evidence_log.jsonl"},
            "changes": changes, "anomalies": anomalies, "served_snapshots": snaps,
            "how_to_verify": ("The .bin snapshots are the exact bytes served at capture time. "
                              "Run verify_chain() on evidence_log.jsonl to prove the log is unedited."),
        }
        base = os.path.join(ev_dir, f"OUTSIDE_EDIT_{ts.replace(':', '')}")
        json.dump(report, open(base + ".json", "w"), indent=2, sort_keys=True)
        with open(base + ".md", "w") as fh:
            fh.write(f"# Unintended edit detected — OUTSIDE Git/Vercel/Claude\n\n"
                     f"**{prop['name']}** — {ts}\n\n{report['meaning']}\n\n"
                     f"Production deployment `{dep_id}` (git `{str(dep_sha)[:10]}`) did **not** change, "
                     f"so no legitimate deploy explains this.\n\n## What changed\n" +
                     "".join(f"- `{c['path']}` — content changed (no deploy)\n" for c in changes) +
                     "".join(f"- `{a['path']}` — {a['kind']}\n" for a in anomalies) +
                     f"\n## Attached evidence\n- `evidence_log.jsonl` entry seq {entry['seq']} "
                     f"(hash `{entry_hash[:16]}...`)\n" +
                     "".join(f"- served bytes: `{s}`\n" for s in snaps))
        attachments = [base + ".json", base + ".md"] + [os.path.join(snap_dir, s) for s in snaps]
        entry["evidence_report"] = [base + ".json", base + ".md"]

    if status_word in cfg["alerts"]["on"] and status_word != "ok":
        tag = "UNINTENDED EDIT (outside pipeline)" if outside else status_word.upper()
        subj = f"[{prop['name']}] {tag} — {len(changes)} changes, {len(anomalies)} anomalies"
        body = (f"{subj}\nTime: {ts}\nProd deploy: {dep_id} (git {str(dep_sha)[:10]}), "
                f"new_deploy={new_deploy}\nOutside Git/Vercel/Claude: {outside}\n"
                f"Changes: {json.dumps(changes)[:1500]}\nAnomalies: {json.dumps(anomalies)[:1500]}\n"
                f"Evidence entry: seq={entry['seq']} hash={entry_hash}\n"
                + ("Evidence (served bytes + report) attached; also on the Action run as an artifact.\n"
                   if outside else ""))
        entry["alerts"] = {"email": send_email(cfg, subj, body, attachments if outside else None),
                           "sms": send_sms_via_email_gateway(cfg, subj)}
    return entry

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    cfg = load_config()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if args.selftest:
        return selftest(cfg, script_dir)
    any_outside = False
    try:
        for prop in cfg["properties"]:
            e = check_property(prop, cfg, script_dir)
            any_outside = any_outside or e.get("outside_pipeline_edit")
            print(f"[{e['timestamp_utc']}] {e['property']}: {e['status']} "
                  f"(seq {e['seq']}, {len(e['changes'])} changes, {len(e['anomalies'])} anomalies, "
                  f"outside_pipeline={e.get('outside_pipeline_edit')})")
    except Exception as ex:
        print(f"MONITOR ERROR: {ex}", file=sys.stderr)
        sys.exit(1)
    sys.exit(2 if any_outside else 0)   # 2 => GitHub Action fails => GitHub emails you

def selftest(cfg, script_dir):
    import tempfile
    tmp = tempfile.mkdtemp(); log = os.path.join(tmp, "evidence_log.jsonl")
    base = {"seq": 0, "timestamp_utc": now_utc(), "property": "selftest", "status": "ok"}
    append_evidence(log, base); append_evidence(log, {**base, "seq": 1})
    ok, n, _ = verify_chain(log)
    lines = open(log).read().splitlines()
    e1 = json.loads(lines[1]); e1["status"] = "TAMPERED"; lines[1] = json.dumps(e1, sort_keys=True)
    open(log, "w").write("\n".join(lines) + "\n")
    ok2, _, bad2 = verify_chain(log)
    print(f"self-test: {n} entries, chain_valid={ok}; after edit chain_valid={ok2} (bad seq {bad2})")
    print("PASS" if (ok and not ok2) else "FAIL")

if __name__ == "__main__":
    main()
