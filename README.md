# httpheaders

Analyze HTTP response headers for security & performance. Zero dependencies.

## Commands

```bash
httpheaders scan github.com       # Security audit with grade
httpheaders raw github.com        # Raw headers
httpheaders raw github.com --json # JSON output
```

## Checks

- **Security headers:** HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP
- **Info leaks:** Server, X-Powered-By, version headers
- **Caching:** Cache-Control, ETag, Last-Modified, Vary

## Grading

A (90%+), B (70%+), C (50%+), D (30%+), F (<30%)

## Requirements

- Python 3.6+ (stdlib only)
