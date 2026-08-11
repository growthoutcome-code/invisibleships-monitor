#!/usr/bin/env python3
"""
site_monitor.py — tamper-evident change monitor for web properties (v1.2).

DEFENSIVE ONLY. Reads the live site (like any visitor), hashes it, and logs.
Never edits the site, database, or repo content. The only thing it writes is its
own append-only evidence log + state.

Confirm-each model (v1.2): the baseline records which production DEPLOYMENT/commit
it was captured from. Each run compares the LIVE deployment to that.

  * Live deploy == baseline deploy, but content differs, or the gate is missing
      -> SERIOUS: a change with no publish, or the gate went down. (exit 2)
  * Live deploy != baseline deploy
      -> PUBLISHED CHANGE pending your confirmation. A calm notice. Nothing is
         auto-accepted; it stays flagged until you regenerate the baseline. (exit 3)
  * Otherwise -> clean. (exit 0)   Monitor error -> exit 1.

The plain-English alert text is written to monitor-state/<property>/latest_alert.md
(+ latest_alert_title.txt) so the workflow can post it verbatim as a GitHub issue
(which GitHub then emails you in full).
"""

import argparse, datetime, hashlib, json, os, smtplib, ssl, sys
from urllib import request as urlrequest, error as urlerror

CONFIG = {
    "state_dir": os.environ.get("MONITOR_STATE_DIR", "./monitor-state"),
    "user_agent": "InvisibleShips-Monitor/1.2 (+integrity-check)",
    "timeout_s": 20,
    "capture_headers": ["date", "age", "server", "x-vercel-id", "x-vercel-cache",
                        "content-type", "content-length", "etag", "last-modified"],
    "properties": [
        {
            "name": "invisibleships.com",
            "base_url": "https://invisibleships.com",
            "pages": ["/", "/journal/is-j01-20250227-entry"],
            "resources": [],   # empty => every resource in the baseline file
            "baseline_file": "site_baseline.invisibleships.json",
            "gate_marker": "18 or older",
            "vercel": {"project_id": "prj_WgklczuymEvBDnkaAFTCYljgQBkF",
                       "team": "growthoutcome", "token_env": "VERCEL_TOKEN"},
        },
    ],
}

# ------------------------------------------------------------------ helpers ---
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

# --------------------------------------------- evidence log (hash-chained) ---
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

# ---------------------------------------------------------------- core pass ---
def check_property(prop, cfg, script_dir):
    state_dir = os.path.join(cfg["state_dir"], prop["name"])
    snap_dir = os.path.join(state_dir, "snapshots")
    ev_dir = os.path.join(state_dir, "evidence")
    os.makedirs(snap_dir, exist_ok=True); os.makedirs(ev_dir, exist_ok=True)
    log_path = os.path.join(state_dir, "evidence_log.jsonl")
    prev_path = os.path.join(state_dir, "last_state.json")
    prev = json.load(open(prev_path)) if os.path.exists(prev_path) else {}

    baseline, baseline_dpl, baseline_sha = {}, None, None
    bf = os.path.join(script_dir, prop.get("baseline_file", ""))
    if os.path.exists(bf):
        bj = json.load(open(bf))
        baseline = bj.get("resources", {})
        baseline_dpl = bj.get("prod_deployment_id")
        baseline_sha = bj.get("git_commit")

    vc = prop.get("vercel", {})
    dep_id, dep_sha = vercel_current_prod(vc, cfg) if vc else (None, None)

    targets = list(prop.get("pages", [])) + (list(prop.get("resources") or baseline.keys()))
    observed, changed_paths, resource_diffs, gate_missing, unreachable = {}, [], [], [], []
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

        note = False
        if is_page and prop.get("gate_marker"):
            present = prop["gate_marker"].encode() in body
            rec["gate_present"] = present
            if not present: gate_missing.append(path); note = True
        if not is_page and path in baseline:
            rec["matches_baseline"] = (rec["sha256"] == baseline[path]["sha256"])
            if not rec["matches_baseline"]: resource_diffs.append(path); note = True

        prev_rec = (prev.get("targets") or {}).get(path, {})
        if prev_rec.get("content_hash") and prev_rec["content_hash"] != rec["content_hash"]:
            changed_paths.append(path); note = True

        if note:
            snap = f"{(path.strip('/').replace('/', '_') or 'root')}.{ts.replace(':', '')}.{rec['sha256'][:12]}.bin"
            with open(os.path.join(snap_dir, snap), "wb") as fh: fh.write(body)
            rec["snapshot"] = snap
        observed[path] = rec

    # ---- classify (confirm-each) --------------------------------------------
    deploy_changed = (dep_id is not None and baseline_dpl is not None and dep_id != baseline_dpl)
    any_diff = bool(resource_diffs or changed_paths)

    if gate_missing:
        verdict = "serious"                        # gate down is always serious
    elif deploy_changed:
        verdict = "published_pending"              # a publish shipped since baseline
    elif any_diff:
        verdict = "serious"                        # changed with no publish -> out of pipeline
    else:
        verdict = "ok"

    entry = {
        "seq": prev.get("seq", -1) + 1, "timestamp_utc": ts, "property": prop["name"],
        "verdict": verdict,
        "live_deployment_id": dep_id, "live_git_sha": dep_sha,
        "baseline_deployment_id": baseline_dpl, "baseline_git_sha": baseline_sha,
        "deploy_changed_from_baseline": deploy_changed,
        "gate_missing": gate_missing, "resource_diffs": resource_diffs,
        "changed_paths": changed_paths, "unreachable": unreachable,
        "targets": observed, "collector": {"host": os.uname().nodename, "tool": "site_monitor.py/1.2"},
    }
    entry_hash = append_evidence(log_path, entry)
    json.dump({"seq": entry["seq"], "targets": observed}, open(prev_path, "w"))

    # ---- plain-English alert (workflow posts this verbatim as an issue) -----
    title_path = os.path.join(state_dir, "latest_alert_title.txt")
    body_path = os.path.join(state_dir, "latest_alert.md")
    key_path = os.path.join(state_dir, "latest_alert_key.txt")   # ASCII, for issue de-dup
    for p in (title_path, body_path, key_path):
        if os.path.exists(p): os.remove(p)

    def bullets():
        out = []
        def _cdiff(p):
            try:
                import glob as _g, re as _re
                rec = observed.get(p) or {}
                newsnap = rec.get("snapshot")
                base = (p.strip("/").replace("/", "_")) or "root"
                snaps = sorted(_g.glob(os.path.join(snap_dir, base + ".*.bin")))
                prev = [s for s in snaps if not (newsnap and s.endswith(newsnap))]
                if not prev or not newsnap:
                    return ""
                old = open(prev[-1], "rb").read().decode("utf-8", "replace")
                new = open(os.path.join(snap_dir, newsnap), "rb").read().decode("utf-8", "replace")
                ow = _re.findall(r"[A-Za-z0-9]+", old)
                nw = _re.findall(r"[A-Za-z0-9]+", new)
                oset, nset = set(ow), set(nw)
                seen = set(); removed = []
                for w in ow:
                    if w not in nset and w not in seen:
                        seen.add(w); removed.append(w)
                seen = set(); added = []
                for w in nw:
                    if w not in oset and w not in seen:
                        seen.add(w); added.append(w)
                parts = []
                if removed: parts.append("removed word(s): " + ", ".join(removed[:8]))
                if added: parts.append("added word(s): " + ", ".join(added[:8]))
                return ("  \u2014 what changed: " + "; ".join(parts)) if parts else ""
            except Exception:
                return ""
        for p in gate_missing:   out.append(f"- The **front-door gate is missing** from `{p}` \u2014 the site may be publicly exposed.")
        for p in resource_diffs: out.append(f"- The file being served at `{p}` **no longer matches the approved version**.{_cdiff(p)}")
        for p in changed_paths:
            if p not in gate_missing and p not in resource_diffs:
                out.append(f"- The content at `{p}` **changed** since the last check.{_cdiff(p)}")
        for p in unreachable:    out.append(f"- `{p}` could not be reached (site down or blocked).")
        return "\n".join(out) or "- (see the evidence file for details)"

    if verdict == "serious":
        title = "⚠️ Possible unauthorized change to invisibleships.com"
        write_report(ev_dir, ts, entry, entry_hash, observed, snap_dir)
        alert = (
            f"An automated integrity check found a problem on **invisibleships.com** at **{ts}** that did "
            f"**not** come through the normal publish process.\n\n"
            f"**What happened:**\n{bullets()}\n\n"
            f"**Why it matters:** the live site is still on the same published version as before "
            f"(deployment `{str(dep_id)[:20]}`, commit `{str(dep_sha)[:10]}`), so nothing was published to "
            f"explain this — the change was made another way.\n\n"
            f"**Is this you?** If not, treat it as a possible unauthorized change (e.g. the gate being shut "
            f"down again).\n\n"
            f"**Evidence** (the exact content served + a tamper-evident record) is attached to this run as the "
            f"**outside-pipeline-evidence** download.\n\n— Invisible Ships site monitor")
        open(title_path, "w").write(title); open(body_path, "w").write(alert)
        open(key_path, "w").write("Possible unauthorized change to invisibleships.com")
    elif verdict == "published_pending":
        title = "📣 A change was published to invisibleships.com — please confirm"
        alert = (
            f"A **new version of invisibleships.com was published** at **{ts}**.\n\n"
            f"- Previously the site was on deployment `{str(baseline_dpl)[:20]}` (commit `{str(baseline_sha)[:10]}`).\n"
            f"- It is now on deployment `{str(dep_id)[:20]}` (commit `{str(dep_sha)[:10]}`).\n\n"
            f"**If this was you** (or someone you authorized), no action needed except to **confirm** it — "
            f"regenerate the monitor's baseline so it treats the new version as the approved one. Until you do, "
            f"this stays flagged.\n\n"
            f"**If this was NOT you,** someone published a change you didn't authorize — investigate the commit "
            f"above.\n\n— Invisible Ships site monitor")
        open(title_path, "w").write(title); open(body_path, "w").write(alert)
        open(key_path, "w").write("A change was published to invisibleships.com")

    return entry

def write_report(ev_dir, ts, entry, entry_hash, observed, snap_dir):
    snaps = [observed[p]["snapshot"] for p in observed if observed[p].get("snapshot")]
    report = {"alert": "SERIOUS_CHANGE_NO_PUBLISH", "timestamp_utc": ts,
              "live_deployment_id": entry["live_deployment_id"], "live_git_sha": entry["live_git_sha"],
              "gate_missing": entry["gate_missing"], "resource_diffs": entry["resource_diffs"],
              "changed_paths": entry["changed_paths"], "served_snapshots": snaps,
              "evidence_log": {"seq": entry["seq"], "entry_hash": entry_hash}}
    base = os.path.join(ev_dir, f"SERIOUS_{ts.replace(':', '')}")
    json.dump(report, open(base + ".json", "w"), indent=2, sort_keys=True)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    cfg = load_config(); script_dir = os.path.dirname(os.path.abspath(__file__))
    if args.selftest: return selftest()
    any_serious = any_published = False
    try:
        for prop in cfg["properties"]:
            e = check_property(prop, cfg, script_dir)
            any_serious = any_serious or e["verdict"] == "serious"
            any_published = any_published or e["verdict"] == "published_pending"
            print(f"[{e['timestamp_utc']}] {e['property']}: {e['verdict']} "
                  f"(live {str(e['live_deployment_id'])[:12]} vs baseline {str(e['baseline_deployment_id'])[:12]})")
    except Exception as ex:
        print(f"MONITOR ERROR: {ex}", file=sys.stderr); sys.exit(1)
    sys.exit(2 if any_serious else 3 if any_published else 0)

def selftest():
    import tempfile
    tmp = tempfile.mkdtemp(); log = os.path.join(tmp, "evidence_log.jsonl")
    base = {"seq": 0, "timestamp_utc": now_utc(), "property": "selftest", "verdict": "ok"}
    append_evidence(log, base); append_evidence(log, {**base, "seq": 1})
    ok, n, _ = verify_chain(log)
    lines = open(log).read().splitlines(); import json as J
    e1 = J.loads(lines[1]); e1["verdict"] = "TAMPERED"; lines[1] = J.dumps(e1, sort_keys=True)
    open(log, "w").write("\n".join(lines) + "\n")
    ok2, _, bad = verify_chain(log)
    print(f"self-test: {n} entries chain_valid={ok}; after edit chain_valid={ok2} (bad seq {bad})")
    print("PASS" if (ok and not ok2) else "FAIL")

if __name__ == "__main__":
    main()
