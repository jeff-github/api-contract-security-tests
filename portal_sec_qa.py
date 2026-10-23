#!/usr/bin/env python3


import argparse, json, os, time, random, datetime
from urllib.parse import urljoin
import urllib.request
import urllib.error

from miniyaml import load_min_yaml


def now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


class HttpClient:
    def __init__(self, base_url: str, timeout: int = 25, min_delay: float = 0.15, max_delay: float = 0.45):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.min_delay = min_delay
        self.max_delay = max_delay

    def request(self, method: str, path: str, bearer_token: str | None, body: str | None, headers: dict | None):
        url = self.base_url + path
        req_headers = {
            "Accept": "application/json",
            "User-Agent": "portal-sec-qa/1.0",
        }
        if headers:
            req_headers.update(headers)
        if bearer_token:
            req_headers["Authorization"] = f"Bearer {bearer_token}"
        data = None
        if body is not None:
            data = body.encode("utf-8")
            req_headers["Content-Type"] = req_headers.get("Content-Type", "application/json")
        # gentle rate-limit
        time.sleep(random.uniform(self.min_delay, self.max_delay))
        req = urllib.request.Request(url=url, data=data, headers=req_headers, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_body = resp.read().decode("utf-8", errors="replace")
                return {
                    "ok": True,
                    "status": resp.status,
                    "headers": dict(resp.headers.items()),
                    "body": resp_body,
                }
        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode("utf-8", errors="replace")
            except Exception:
                err_body = ""
            return {
                "ok": False,
                "status": e.code,
                "headers": dict(e.headers.items()) if e.headers else {},
                "body": err_body,
                "error": str(e),
            }
        except Exception as e:
            return {
                "ok": False,
                "status": None,
                "headers": {},
                "body": "",
                "error": repr(e),
            }


def safe_snip(s: str, limit: int = 1200) -> str:
    if s is None:
        return ""
    s = s.strip()
    if len(s) <= limit:
        return s
    return s[:limit] + f"\n...[snipped {len(s)-limit} chars]"


def make_dirs(p: str):
    os.makedirs(p, exist_ok=True)


def write_raw(out_dir: str, test_id: str, content: dict):
    raw_dir = os.path.join(out_dir, "raw")
    make_dirs(raw_dir)
    path = os.path.join(raw_dir, f"{test_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(content, f, indent=2, ensure_ascii=False)
    return path


def verdict(status: int | None, allow: bool):
    if status is None:
        return "ERROR"
    if allow:
        return "PASS" if status < 400 else "FAIL"
    # deny expected
    return "PASS" if status in (401, 403, 404) else "FAIL"


def run_rbac_matrix(client: HttpClient, endpoint: dict, roles: dict, patient_id: str, out_dir: str):
    results = []
    method = endpoint["method"].upper()
    path_tpl = endpoint["path"]
    path = path_tpl.replace("{patient_id}", patient_id)
    expected_allow = set(endpoint.get("expected", {}).get("allow_roles", []))

    for role, token in roles.items():
        allow = role in expected_allow
        resp = client.request(method, path, token, body="{}" if method in ("POST","PUT","PATCH") else None, headers=None)
        tid = f"rbac_{endpoint['name'].replace(' ','_')}_{role}_{patient_id}".replace("/","_")
        raw_path = write_raw(out_dir, tid, {
            "test": "rbac_matrix",
            "endpoint": endpoint,
            "role": role,
            "patient_id": patient_id,
            "request": {"method": method, "path": path},
            "response": {"status": resp["status"], "headers": resp["headers"], "body": safe_snip(resp["body"])},
            "timestamp": now_iso(),
        })
        results.append({
            "id": tid,
            "type": "RBAC",
            "endpoint": endpoint["name"],
            "role": role,
            "patient_id": patient_id,
            "expected": "ALLOW" if allow else "DENY",
            "observed_status": resp["status"],
            "verdict": verdict(resp["status"], allow),
            "raw": raw_path,
        })
    return results


def run_idor_check(client: HttpClient, endpoint: dict, roles: dict, role_for_idor: str, in_scope_id: str, out_scope_id: str, out_dir: str):
    # IDOR concept check: same role, different object ids.
    # Secure systems should deny access to out-of-scope objects (403/404) and avoid leaking state via distinct messages.
    method = endpoint["method"].upper()
    path_tpl = endpoint["path"]
    token = roles.get(role_for_idor)
    if not token:
        return [{
            "id": f"idor_{endpoint['name'].replace(' ','_')}",
            "type": "IDOR",
            "endpoint": endpoint["name"],
            "role": role_for_idor,
            "patient_id": None,
            "expected": "Configured role token required",
            "observed_status": None,
            "verdict": "SKIP",
            "raw": None,
        }]

    def call(pid: str):
        path = path_tpl.replace("{patient_id}", pid)
        return client.request(method, path, token, body="{}" if method in ("POST","PUT","PATCH") else None, headers=None), path

    r_in, p_in = call(in_scope_id)
    r_out, p_out = call(out_scope_id)

    tid = f"idor_{endpoint['name'].replace(' ','_')}_{role_for_idor}_{in_scope_id}_vs_{out_scope_id}".replace("/","_")
    raw_path = write_raw(out_dir, tid, {
        "test": "idor_check",
        "endpoint": endpoint,
        "role": role_for_idor,
        "in_scope": {"patient_id": in_scope_id, "request": {"method": method, "path": p_in}, "response": {"status": r_in["status"], "body": safe_snip(r_in["body"])}},
        "out_of_scope": {"patient_id": out_scope_id, "request": {"method": method, "path": p_out}, "response": {"status": r_out["status"], "body": safe_snip(r_out["body"])}},
        "timestamp": now_iso(),
        "note": "A potential issue is indicated if out-of-scope is not denied, or if errors leak distinct workflow details."
    })

    # verdict logic (conservative)
    out_denied = (r_out["status"] in (401,403,404))
    in_ok_or_known = (r_in["status"] is not None)
    # If out-of-scope not denied, fail.
    # If denied but returns detailed body, still flag as WARN.
    v = "PASS" if out_denied else "FAIL"
    flags = []
    if out_denied:
        # heuristic leak: different body mentions state like connected/not_connected/pending/etc.
        leak_words = ["connected", "not_connected", "pending", "active", "trial", "status"]
        out_body = (r_out.get("body") or "").lower()
        if any(w in out_body for w in leak_words) and len(out_body) > 0:
            flags.append("Potential information disclosure in out-of-scope error message.")
            v = "WARN"
    return [{
        "id": tid,
        "type": "IDOR",
        "endpoint": endpoint["name"],
        "role": role_for_idor,
        "patient_id": f"{in_scope_id} vs {out_scope_id}",
        "expected": "Out-of-scope access denied (403/404) with minimal disclosure",
        "observed_status": f"in_scope={r_in['status']}, out_scope={r_out['status']}",
        "verdict": v,
        "flags": flags,
        "raw": raw_path,
    }]


def run_state_transition(client: HttpClient, endpoint: dict, roles: dict, patient_id: str, out_dir: str):
    st = endpoint.get("state_transition")
    if not st:
        return []
    kind = st.get("kind")
    if kind != "idempotent_post":
        return []
    method = endpoint["method"].upper()
    if method != "POST":
        return []

    allow_roles = endpoint.get("expected", {}).get("allow_roles", [])
    role = allow_roles[0] if allow_roles else next(iter(roles.keys()), None)
    token = roles.get(role) if role else None
    if not token:
        return [{
            "id": f"state_{endpoint['name'].replace(' ','_')}_{patient_id}",
            "type": "STATE",
            "endpoint": endpoint["name"],
            "role": role,
            "patient_id": patient_id,
            "expected": "role token required",
            "observed_status": None,
            "verdict": "SKIP",
            "raw": None,
        }]

    replay = int(st.get("replay", 3))
    success_statuses = set(st.get("success_statuses", [200]))
    repeat_statuses = set(st.get("repeat_statuses", [409, 400]))

    path = endpoint["path"].replace("{patient_id}", patient_id)

    attempts = []
    verdicts = []
    for i in range(1, replay+1):
        resp = client.request("POST", path, token, body="{}", headers=None)
        attempts.append({"attempt": i, "status": resp["status"], "body": safe_snip(resp["body"], 600)})
        # Evaluate: first is allowed to be success or already-done
        if i == 1:
            if resp["status"] in success_statuses or resp["status"] in repeat_statuses:
                verdicts.append("ok")
            else:
                verdicts.append("bad")
        else:
            if resp["status"] in repeat_statuses:
                verdicts.append("ok")
            else:
                verdicts.append("bad")

    tid = f"state_{endpoint['name'].replace(' ','_')}_{role}_{patient_id}".replace("/","_")
    raw_path = write_raw(out_dir, tid, {
        "test": "state_transition",
        "endpoint": endpoint,
        "role": role,
        "patient_id": patient_id,
        "request": {"method":"POST", "path": path},
        "attempts": attempts,
        "timestamp": now_iso(),
        "expected": {"first": list(success_statuses) + list(repeat_statuses), "repeat": list(repeat_statuses)},
    })
    v = "PASS" if all(x=="ok" for x in verdicts) else "FAIL"
    return [{
        "id": tid,
        "type": "STATE",
        "endpoint": endpoint["name"],
        "role": role,
        "patient_id": patient_id,
        "expected": f"First: {sorted(success_statuses|repeat_statuses)}; Repeats: {sorted(repeat_statuses)}",
        "observed_status": ", ".join([f"{a['attempt']}:{a['status']}" for a in attempts]),
        "verdict": v,
        "raw": raw_path,
    }]


def render_report(results: list[dict], meta: dict, out_dir: str):
    make_dirs(out_dir)
    # JSON
    report_json = {
        "meta": meta,
        "results": results,
        "summary": summarize(results),
    }
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report_json, f, indent=2, ensure_ascii=False)

    # HTML
    html = []
    html.append("<html><head><meta charset='utf-8'>")
    html.append("<style>body{font-family:system-ui,Segoe UI,Arial;margin:24px} table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:8px;font-size:13px} th{background:#f5f5f5;text-align:left} .PASS{color:green;font-weight:700} .FAIL{color:#b00020;font-weight:700} .WARN{color:#b26a00;font-weight:700} .SKIP{color:#666;font-weight:700}</style>")
    html.append("</head><body>")
    html.append(f"<h1>Portal Security QA Report</h1>")
    html.append("<h3>Run Metadata</h3>")
    html.append("<ul>")
    for k,v in meta.items():
        html.append(f"<li><b>{k}</b>: {v}</li>")
    html.append("</ul>")

    summ = report_json["summary"]
    html.append("<h3>Summary</h3>")
    html.append("<ul>")
    html.append(f"<li><b>Total</b>: {summ['total']}</li>")
    html.append(f"<li><span class='PASS'>PASS</span>: {summ['PASS']}</li>")
    html.append(f"<li><span class='WARN'>WARN</span>: {summ['WARN']}</li>")
    html.append(f"<li><span class='FAIL'>FAIL</span>: {summ['FAIL']}</li>")
    html.append(f"<li><span class='SKIP'>SKIP</span>: {summ['SKIP']}</li>")
    html.append("</ul>")

    html.append("<h3>Results</h3>")
    html.append("<table>")
    html.append("<tr><th>Verdict</th><th>Type</th><th>Endpoint</th><th>Role</th><th>Patient</th><th>Expected</th><th>Observed</th><th>Evidence</th></tr>")
    for r in results:
        v = r.get("verdict","")
        raw = r.get("raw")
        evidence = f"<a href='raw/{os.path.basename(raw)}'>raw</a>" if raw else ""
        html.append(f"<tr><td class='{v}'>{v}</td><td>{r.get('type','')}</td><td>{r.get('endpoint','')}</td><td>{r.get('role','')}</td><td>{r.get('patient_id','')}</td><td>{r.get('expected','')}</td><td>{r.get('observed_status','')}</td><td>{evidence}</td></tr>")
        flags = r.get("flags") or []
        if flags:
            html.append(f"<tr><td></td><td colspan='7'><b>Flags:</b> " + " | ".join(flags) + "</td></tr>")
    html.append("</table>")
    html.append("<p style='margin-top:16px;color:#666'>Generated by portal-sec-qa/1.0</p>")
    html.append("</body></html>")

    with open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8") as f:
        f.write("\n".join(html))


def summarize(results: list[dict]):
    counts = {"PASS":0,"FAIL":0,"WARN":0,"SKIP":0}
    for r in results:
        v = r.get("verdict","SKIP")
        if v not in counts:
            counts[v]=0
        counts[v]+=1
    counts["total"]=len(results)
    return counts


def main():
    ap = argparse.ArgumentParser(description="Authorized Portal Security QA Validator")
    ap.add_argument("--config", required=True, help="Path to config.yaml")
    ap.add_argument("--out", default="out", help="Output directory")
    args = ap.parse_args()

    cfg_text = open(args.config, "r", encoding="utf-8").read()
    cfg = load_min_yaml(cfg_text)

    base_url = cfg["base_url"]
    roles = cfg.get("roles", {})
    patients = cfg.get("patients", {})
    in_scope = patients.get("in_scope", [])
    out_scope = patients.get("out_of_scope", [])
    endpoints = cfg.get("endpoints", [])

    client = HttpClient(base_url)

    meta = {
        "base_url": base_url,
        "run_at": now_iso(),
        "endpoints": len(endpoints),
        "roles": ", ".join(list(roles.keys())),
        "in_scope_patients": ", ".join(in_scope[:5]) + ("..." if len(in_scope) > 5 else ""),
        "out_scope_patients": ", ".join(out_scope[:5]) + ("..." if len(out_scope) > 5 else ""),
    }

    results = []

    # RBAC matrix over in-scope patient IDs
    for ep in endpoints:
        name = ep.get("name","(unnamed)")
        # Pick a representative patient id for RBAC checks
        pid = in_scope[0] if in_scope else "TEST"
        results.extend(run_rbac_matrix(client, ep, roles, pid, args.out))
        # State transition checks if configured
        if in_scope:
            results.extend(run_state_transition(client, ep, roles, in_scope[0], args.out))

        # IDOR check if we have both
        if in_scope and out_scope:
            # Use first allow role if available
            allow_roles = ep.get("expected", {}).get("allow_roles", [])
            role_for_idor = allow_roles[0] if allow_roles else next(iter(roles.keys()))
            results.extend(run_idor_check(client, ep, roles, role_for_idor, in_scope[0], out_scope[0], args.out))

    render_report(results, meta, args.out)
    print(f"Done. Reports written to: {os.path.abspath(args.out)}")
    print(f"- {os.path.join(os.path.abspath(args.out),'report.html')}")
    print(f"- {os.path.join(os.path.abspath(args.out),'report.json')}")


if __name__ == "__main__":
    main()
