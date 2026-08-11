#!/usr/bin/env python3
"""3x/day digest: compare LIVE production (pages + downloadable corpus) to the
approved baseline reference and email a plain-English summary + word-level diff."""
import os, json, re, sys, smtplib, ssl
from email.mime.text import MIMEText
import site_monitor as sm

NL = chr(10)

def words(b):
    try:
        t = b.decode("utf-8", "replace")
    except Exception:
        t = ""
    return re.findall(r"[A-Za-z0-9]+", t)

def word_diff(old_b, new_b, limit=15):
    ow, nw = words(old_b), words(new_b)
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
    if removed:
        parts.append("removed word(s): " + ", ".join(removed[:limit]) + (" ..." if len(removed) > limit else ""))
    if added:
        parts.append("added word(s): " + ", ".join(added[:limit]) + (" ..." if len(added) > limit else ""))
    return "; ".join(parts)

def send_email(subject, body):
    host = os.environ.get("SMTP_HOST"); user = os.environ.get("SMTP_USER")
    pw = os.environ.get("SMTP_PASS"); to = os.environ.get("ALERT_TO")
    frm = os.environ.get("ALERT_FROM") or user
    try:
        port = int(os.environ.get("SMTP_PORT") or 587)
    except Exception:
        port = 587
    if not (host and user and pw and to):
        print("SMTP not configured; digest delivered via commit push email instead.")
        return
    msg = MIMEText(body); msg["Subject"] = subject; msg["From"] = frm; msg["To"] = to
    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(host, port) as s:
            s.starttls(context=ctx); s.login(user, pw); s.sendmail(frm, [to], msg.as_string())
        print("digest email sent to", to)
    except Exception as e:
        print("SMTP send failed:", e)

def main():
    cfg = sm.load_config(); prop = cfg["properties"][0]
    base_url = prop["base_url"].rstrip("/")
    state_dir = os.path.join(cfg["state_dir"], prop["name"])
    ref_dir = os.path.join(state_dir, "reference"); os.makedirs(ref_dir, exist_ok=True)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    baseline = json.load(open(os.path.join(script_dir, prop["baseline_file"])))
    b_res = baseline.get("resources", {}); b_commit = baseline.get("git_commit")
    b_dpl = baseline.get("prod_deployment_id")
    meta_path = os.path.join(ref_dir, "_meta.json")
    try:
        meta = json.load(open(meta_path))
    except Exception:
        meta = {}
    ref_stale = meta.get("baseline_commit") != b_commit
    ts = sm.now_utc()
    targets = list(prop.get("pages", [])) + list(b_res.keys())
    lines = []; changed = 0; unreachable = 0
    for path in targets:
        is_page = path in prop.get("pages", [])
        url = base_url + path
        status, body, hdrs = sm.fetch(url, cfg)
        refname = (path.strip("/").replace("/", "_")) or "root"
        refpath = os.path.join(ref_dir, refname)
        if body is None:
            unreachable += 1
            lines.append("- " + path + " could not be reached (status " + str(status) + ").")
            continue
        if ref_stale or not os.path.exists(refpath):
            open(refpath, "wb").write(body); continue
        old = open(refpath, "rb").read()
        if sm.sha256_bytes(old) != sm.sha256_bytes(body):
            changed += 1; d = word_diff(old, body)
            what = "page" if is_page else "file"
            lines.append("- " + what + " " + path + " CHANGED (" + str(len(old)) + " B -> " + str(len(body)) + " B)" + ((" -- " + d) if d else ""))
            open(refpath, "wb").write(body)
    dep_line = None
    try:
        vc = prop.get("vercel", {})
        dep_id, dep_sha = sm.vercel_current_prod(vc, cfg) if vc else (None, None)
        if dep_id and b_dpl and dep_id != b_dpl:
            dep_line = "- Live is on a NEWER deployment (commit " + str(dep_sha)[:10] + ") than the approved baseline (" + str(b_commit)[:10] + "). If this was you, regenerate the baseline to approve it."
    except Exception:
        pass
    if ref_stale:
        json.dump({"baseline_commit": b_commit}, open(meta_path, "w"))
    if changed or dep_line or unreachable:
        n = changed + (1 if dep_line else 0) + unreachable
        summary = "Digest " + ts + " -- " + str(n) + " change(s)/issue(s) detected"
        body_lines = [summary, "", "Live production differs from your approved baseline:"]
        if dep_line:
            body_lines.append(dep_line)
        body_lines += lines
    else:
        summary = "Digest " + ts + " -- no changes (live matches approved baseline)"
        body_lines = [summary, "", "No changes. Live production matches your approved baseline (commit " + str(b_commit)[:10] + ", deploy " + str(b_dpl) + "). All " + str(len(b_res)) + " corpus files and " + str(len(prop.get("pages", []))) + " page(s) match."]
    if ref_stale:
        body_lines += ["", "(Reference synced to current baseline " + str(b_commit)[:10] + ".)"]
    report = NL.join(body_lines); print(report)
    open(os.path.join(state_dir, "LATEST_DIGEST.md"), "w").write(report + NL)
    send_email("[Invisible Ships monitor] " + summary, report)

if __name__ == "__main__":
    main()
