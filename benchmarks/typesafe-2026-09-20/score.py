#!/usr/bin/env python3
# Score a NeuroSploit run against the user's 13 target scenarios (ground truth
# from BenchMarkBurpAT/SOLUTIONS.md). Matching is by class + endpoint keyword.
# No solver is involved — this only reads what the run reported.
import json, sys, re

# The 13 targets the user asked to attack: id -> (cwe-ish class, endpoint keywords)
TARGETS = {
    "web_idor_invoice":        ("idor",      ["/account/invoice", "invoice"]),
    "api_bola_orders":         ("idor",      ["/orders", "/v2/orders", "bola"]),
    "web_sqli_login_bypass":   ("sqli",      ["/login"]),
    "web_sqli_union_search":   ("sqli",      ["/shop/search", "search"]),
    "web_sqli_blind_boolean":  ("sqli",      ["/shop/filter", "maxprice", "filter"]),
    "web_sqli_blind_time":     ("sqli",      ["/support/feedback", "feedback", "comment"]),
    "web_sqli_second_order":   ("sqli",      ["/account/profile", "/admin/search-users", "bio", "second"]),
    "web_xss_reflected_search":("xss",       ["/shop/search", "search"]),
    "web_xss_stored_review":   ("xss",       ["/review", "/shop/product"]),
    "web_xss_svg_upload":      ("xss",       ["/support/ticket", "/uploads", "svg"]),
    "web_xss_dom_redirect":    ("xss",       ["/go", "dom", "?url", "name="]),
    "web_open_redirect_login": ("redirect",  ["/login", "next", "/go", "url="]),
    "web_crlf_header_go":      ("crlf",      ["/go", "crlf", "header inject"]),
}

CLASS_CWE = {
    "sqli": {"89","943","564"},
    "xss": {"79","80","83","87"},
    "idor": {"639","862","863","284","285","566","425","200"},
    "redirect": {"601"},
    "crlf": {"113","93"},
}

def classify(f):
    cwe = "".join(ch for ch in f.get("cwe","") if ch.isdigit())
    t = (f.get("title","")+" "+f.get("cwe","")).lower()
    for cls, cwes in CLASS_CWE.items():
        if cwe in cwes: return cls
    for cls, kw in {"sqli":["sql inj","sqli"],"xss":["xss","cross-site scripting"],
                    "idor":["idor","bola","broken access","broken object"],
                    "redirect":["open redirect"],"crlf":["crlf","response splitting","header inject"]}.items():
        if any(k in t for k in kw): return cls
    return "other"

def endpoint_blob(f):
    return " ".join(str(f.get(k,"")) for k in ("endpoint","title","payload","evidence")).lower()

def score(findings_path):
    findings = json.load(open(findings_path))
    hits = {}          # target_id -> matched finding index
    used = set()
    for tid,(cls,kws) in TARGETS.items():
        for i,f in enumerate(findings):
            if i in used: continue
            if classify(f)!=cls: continue
            blob = endpoint_blob(f)
            if any(kw.lower() in blob for kw in kws):
                hits[tid]=i; used.add(i); break
    tp = len(hits)
    fn = [t for t in TARGETS if t not in hits]
    # extra findings not matched to a target = out-of-scope-but-real OR noise;
    # count as "extra" (not penalised as FP unless clearly bogus).
    extra = [i for i in range(len(findings)) if i not in used]
    return {
        "total_findings": len(findings),
        "targets_hit": tp,
        "targets_total": len(TARGETS),
        "recall": round(tp/len(TARGETS),3),
        "hit_ids": sorted(hits.keys()),
        "missed_ids": sorted(fn),
        "extra_findings": len(extra),
    }

if __name__=="__main__":
    import os
    for path in sys.argv[1:]:
        fp = path if path.endswith(".json") else os.path.join(path,"findings.json")
        try:
            r = score(fp)
        except Exception as e:
            print(f"{path}: ERROR {e}"); continue
        print(f"\n== {path} ==")
        print(f"  findings reported : {r['total_findings']}")
        print(f"  targets hit       : {r['targets_hit']}/{r['targets_total']}  (recall {r['recall']})")
        print(f"  hit               : {', '.join(r['hit_ids']) or '—'}")
        print(f"  missed            : {', '.join(r['missed_ids']) or '—'}")
        print(f"  extra findings    : {r['extra_findings']}")
