#!/usr/bin/env python3
"""httpheaders - Analyze HTTP response headers for security & performance. Zero deps."""
import sys, urllib.request, ssl, json

SECURITY_HEADERS = {
    "strict-transport-security": {"required": True, "desc": "HSTS — force HTTPS"},
    "content-security-policy": {"required": True, "desc": "CSP — prevent XSS/injection"},
    "x-content-type-options": {"required": True, "desc": "Prevent MIME sniffing", "expected": "nosniff"},
    "x-frame-options": {"required": True, "desc": "Prevent clickjacking"},
    "referrer-policy": {"required": True, "desc": "Control referrer leaks"},
    "permissions-policy": {"required": False, "desc": "Restrict browser features"},
    "x-xss-protection": {"required": False, "desc": "Legacy XSS filter"},
    "cross-origin-opener-policy": {"required": False, "desc": "Isolate browsing context"},
    "cross-origin-resource-policy": {"required": False, "desc": "Block cross-origin reads"},
    "cross-origin-embedder-policy": {"required": False, "desc": "Require CORP for embeds"},
}

LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]

def fetch_headers(url, follow=True):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "httpheaders/1.0"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            return dict(resp.headers), resp.status, resp.url
    except urllib.error.HTTPError as e:
        return dict(e.headers), e.code, url

def cmd_scan(args):
    if not args: print("Usage: httpheaders scan <url>"); sys.exit(1)
    url = args[0]
    if not url.startswith("http"): url = "https://" + url
    
    headers, status, final_url = fetch_headers(url)
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    print(f"🔍 Header Analysis: {final_url}")
    print(f"   Status: {status}\n")
    
    # Security headers
    print("🔒 Security Headers:")
    score = 0; total = 0
    for h, info in SECURITY_HEADERS.items():
        total += 1
        val = headers_lower.get(h)
        if val:
            score += 1
            expected = info.get("expected")
            if expected and val.strip().lower() != expected.lower():
                print(f"  ⚠️  {h}: {val} (expected: {expected})")
            else:
                print(f"  ✅ {h}: {val[:80]}")
        elif info["required"]:
            print(f"  ❌ {h} — MISSING ({info['desc']})")
        else:
            print(f"  ➖ {h} — not set ({info['desc']})")
    
    # Info leaks
    print("\n🕵️ Information Leaks:")
    leaks = 0
    for h in LEAKY_HEADERS:
        val = headers_lower.get(h)
        if val:
            print(f"  ⚠️  {h}: {val}")
            leaks += 1
    if not leaks:
        print("  ✅ No server info leaked")
    
    # Cache
    print("\n⚡ Caching:")
    for h in ["cache-control", "etag", "last-modified", "age", "expires", "vary"]:
        val = headers_lower.get(h)
        if val: print(f"  📌 {h}: {val}")
    
    # Score
    pct = round(score / total * 100)
    grade = "A" if pct >= 90 else "B" if pct >= 70 else "C" if pct >= 50 else "D" if pct >= 30 else "F"
    print(f"\n{'='*40}")
    print(f"Score: {score}/{total} ({pct}%) — Grade: {grade}")

def cmd_raw(args):
    if not args: print("Usage: httpheaders raw <url>"); sys.exit(1)
    url = args[0]
    if not url.startswith("http"): url = "https://" + url
    headers, status, _ = fetch_headers(url)
    if "--json" in args:
        print(json.dumps(headers, indent=2))
    else:
        print(f"HTTP {status}")
        for k, v in sorted(headers.items()):
            print(f"{k}: {v}")

CMDS = {"scan": cmd_scan, "raw": cmd_raw}

if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] in ("-h","--help"):
        print("httpheaders - HTTP header security analyzer")
        print("Commands: scan <url>, raw <url> [--json]")
        sys.exit(0)
    cmd = args[0]
    if cmd not in CMDS: print(f"Unknown: {cmd}"); sys.exit(1)
    CMDS[cmd](args[1:])
