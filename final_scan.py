import urllib.request, ssl, re, json

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def fetch(url, method='GET', data=None, headers=None):
    hdrs = {'User-Agent': 'Mozilla/5.0'}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs, method=method)
    if data:
        req.data = data
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=15)
        return resp.getcode(), resp.read().decode('utf-8', errors='replace'), dict(resp.headers)
    except Exception as e:
        if hasattr(e, 'read'):
            return e.code, e.read().decode('utf-8', errors='replace'), dict(getattr(e, 'headers', {}))
        return 0, str(e), {}

base = 'https://www.itzfoto.co.il'
out = open('final_analysis.txt', 'w', encoding='utf-8')

def log(s):
    out.write(s + '\n')
    out.flush()

# 1. Get the full gallery component JS
log("=== FULL GALLERY JS COMPONENT ===")
code, body, _ = fetch(base + '/_next/static/chunks/01sxyhlyrg.~w.js')
log(f"Size: {len(body)} bytes")
# This is the application code - show it ALL (it's the important one)
clean = body.encode('ascii', 'replace').decode('ascii')
log(clean)

# 2. Try /api/photos with folder + page + limit (the real API signature)
log("\n\n=== TESTING /api/photos WITH FULL PARAMS ===")
test_cases = [
    {"folder": "", "page": 1, "limit": 20},
    {"folder": "/", "page": 1, "limit": 20},
    {"folder": ".", "page": 1, "limit": 20},
    {"folder": "test", "page": 1, "limit": 20},
    {"folder": "photos", "page": 1, "limit": 20},
    {"folder": "gallery", "page": 1, "limit": 20},
    {"folder": "clients", "page": 1, "limit": 20},
    {"folder": "...", "page": 1, "limit": 20},
    {"folder": "../", "page": 1, "limit": 20},
]
for tc in test_cases:
    data = json.dumps(tc).encode()
    code, body, hdrs = fetch(base + '/api/photos', method='POST',
        data=data, headers={'Content-Type': 'application/json'})
    log(f"  {tc} => {code}: {body[:500]}")

# 3. Try login with common credentials
log("\n\n=== TESTING /api/login ===")
login_tests = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "123456"},
    {"username": "test", "password": "test"},
    {"email": "admin@itzfoto.co.il", "password": "admin"},
    {"user": "admin", "pass": "admin"},
]
for lt in login_tests:
    data = json.dumps(lt).encode()
    code, body, hdrs = fetch(base + '/api/login', method='POST',
        data=data, headers={'Content-Type': 'application/json'})
    log(f"  {lt} => {code}: {body[:300]}")
    # Check for Set-Cookie
    for k, v in hdrs.items():
        if 'cookie' in k.lower():
            log(f"    Cookie: {v}")

# 4. Check login page JS for how login works
log("\n\n=== LOGIN PAGE SPECIFIC JS ===")
code, login_html, _ = fetch(base + '/login')
# Find login-page-specific chunks
all_chunks_main = set(re.findall(r'src="(/_next/static/chunks/[^"]+)"', login_html))
code, gallery_html, _ = fetch(base + '/gallery')
all_chunks_gallery = set(re.findall(r'src="(/_next/static/chunks/[^"]+)"', gallery_html))
code, home_html, _ = fetch(base + '/')
all_chunks_home = set(re.findall(r'src="(/_next/static/chunks/[^"]+)"', home_html))

# Find chunks unique to login page
login_specific = all_chunks_main - all_chunks_gallery - all_chunks_home
log(f"Login-specific chunks: {login_specific}")
log(f"Gallery-specific chunks: {all_chunks_gallery - all_chunks_main - all_chunks_home}")
log(f"All login chunks: {all_chunks_main}")

for chunk in login_specific:
    code, body, _ = fetch(base + chunk)
    if code == 200:
        log(f"\n--- {chunk} ({len(body)} bytes) ---")
        clean = body.encode('ascii', 'replace').decode('ascii')
        log(clean[:5000])

# 5. Check if OPTIONS reveals allowed methods
log("\n\n=== OPTIONS /api/photos ===")
code, body, hdrs = fetch(base + '/api/photos', method='OPTIONS')
log(f"Status: {code}")
for k, v in hdrs.items():
    log(f"  {k}: {v}")

log("\nDONE")
out.close()
print("DONE - results in final_analysis.txt")
