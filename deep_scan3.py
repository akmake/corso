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
out = open('deep_results2.txt', 'w', encoding='utf-8')

def log(s):
    out.write(s + '\n')
    out.flush()

# 1. Gallery page full content
log("=== GALLERY PAGE (full) ===")
code, body, hdrs = fetch(base + '/gallery')
log(f"Status: {code}, Size: {len(body)}")
# Remove non-ascii for safety
clean = body.encode('ascii', 'replace').decode('ascii')
log(clean[:5000])

# 2. Try POST to /api/photos with different payloads
log("\n=== POST /api/photos (empty) ===")
code, body, hdrs = fetch(base + '/api/photos', method='POST',
    data=b'{}', headers={'Content-Type': 'application/json'})
log(f"Status: {code}, Body: {body[:2000]}")

# 3. Try with folder/user params
log("\n=== POST /api/photos with params ===")
test_payloads = [
    {'folder': 'test'},
    {'userId': 'test'},
    {'user': 'test'},
    {'path': '/'},
    {'gallery': 'test'},
    {'id': '1'},
    {'username': 'admin'},
]
for payload in test_payloads:
    data = json.dumps(payload).encode()
    code, body, hdrs = fetch(base + '/api/photos', method='POST',
        data=data, headers={'Content-Type': 'application/json'})
    log(f"  POST {payload} => {code}: {body[:300]}")

# 4. Try other API patterns
log("\n=== TRYING MORE API PATTERNS ===")
api_paths = [
    '/api/auth/login', '/api/auth/signin', '/api/login', '/api/verify',
    '/api/token', '/api/photo', '/api/image', '/api/file', '/api/files',
    '/api/list', '/api/share', '/api/shared', '/api/link', '/api/links',
    '/api/dropbox/list', '/api/dropbox/files', '/api/get-photos',
    '/api/get-images', '/api/client', '/api/clients',
    '/api/download', '/api/thumb', '/api/thumbnail', '/api/thumbnails',
    '/api/select', '/api/selected', '/api/favorites',
]
for p in api_paths:
    code, body, hdrs = fetch(base + p)
    if code != 404:
        log(f"  GET {p} => {code}: {body[:300]}")
    code2, body2, hdrs2 = fetch(base + p, method='POST',
        data=b'{}', headers={'Content-Type': 'application/json'})
    if code2 != 404:
        log(f"  POST {p} => {code2}: {body2[:300]}")

# 5. Login page analysis
log("\n=== LOGIN PAGE ANALYSIS ===")
code, body, hdrs = fetch(base + '/login')
log(f"Login page status: {code}, size: {len(body)}")
for pattern in [r'action=["\']([^"\']+)', r'fetch\(["\']([^"\']+)', r'/api/[a-zA-Z0-9/_-]+', r'dropbox', r'dbx']:
    matches = re.findall(pattern, body, re.IGNORECASE)
    if matches:
        log(f"  Pattern [{pattern}]: {matches[:10]}")

# Look specifically for the login JS chunk
log("\n=== PAGE-SPECIFIC JS CHUNKS ===")
# Extract JS files from gallery page
code, body, hdrs = fetch(base + '/gallery')
js_files = re.findall(r'src="(/_next/static/chunks/[^"]+)"', body)
log(f"Gallery JS files: {js_files}")

# Now fetch the gallery-specific chunk and look for dropbox/API patterns
for js in js_files:
    code, jsbody, _ = fetch(base + js)
    if code == 200:
        has_interesting = False
        for kw in ['dropbox', 'dbx', 'api/photos', 'api/photo', 'gallery', 'folder', 'token', 'fetch(', 'authorization', 'password', 'selected', 'download']:
            if kw.lower() in jsbody.lower():
                has_interesting = True
                idx = jsbody.lower().find(kw.lower())
                snippet = jsbody[max(0,idx-150):idx+len(kw)+150]
                clean_snip = snippet.encode('ascii', 'replace').decode('ascii')
                log(f"  {js} [{kw}]: ...{clean_snip}...")
        if not has_interesting:
            log(f"  {js}: no interesting patterns ({len(jsbody)} bytes)")

# 6. Response headers
log("\n=== RESPONSE HEADERS (/) ===")
code, body, hdrs = fetch(base + '/')
for k, v in hdrs.items():
    log(f"  {k}: {v}")

# 7. Try direct paths to user galleries with common names
log("\n=== TRYING DIRECT GALLERY PATHS ===")
gallery_paths = [
    '/gallery/1', '/gallery/test', '/gallery/admin', '/gallery/demo',
    '/client/1', '/client/test', '/photos/1', '/photos/test',
    '/user/1', '/user/test', '/album/1', '/album/test',
    '/event/1', '/event/test',
]
for gp in gallery_paths:
    code, body, hdrs = fetch(base + gp)
    if code != 404:
        log(f"  GET {gp} => {code} ({len(body)} bytes)")
        # Check if it contains actual images
        imgs = re.findall(r'src=["\']([^"\']*(?:jpg|jpeg|png|webp|dropbox)[^"\']*)', body, re.IGNORECASE)
        if imgs:
            log(f"    IMAGES FOUND: {imgs[:5]}")

log("\nDONE")
out.close()
