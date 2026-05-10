import urllib.request, ssl, re, json, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

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
results = []

# 1. Gallery page full content
print("=== GALLERY PAGE (full) ===", flush=True)
code, body, hdrs = fetch(base + '/gallery')
print(f"Status: {code}, Size: {len(body)}", flush=True)
print(body[:5000], flush=True)

# 2. Try POST to /api/photos with different payloads
print("\n\n=== POST /api/photos (empty) ===", flush=True)
code, body, hdrs = fetch(base + '/api/photos', method='POST', 
    data=b'{}', headers={'Content-Type': 'application/json'})
print(f"Status: {code}, Body: {body[:2000]}", flush=True)

# 3. Try with a generic folder/user ID
print("\n\n=== POST /api/photos with folder param ===", flush=True)
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
    print(f"  POST {payload} => {code}: {body[:300]}", flush=True)

# 4. Try other API patterns
print("\n\n=== TRYING MORE API PATTERNS ===", flush=True)
api_paths = [
    '/api/auth/login',
    '/api/auth/signin', 
    '/api/login',
    '/api/verify',
    '/api/token',
    '/api/photo',
    '/api/image',
    '/api/file',
    '/api/files',
    '/api/list',
    '/api/share',
    '/api/shared',
    '/api/link',
    '/api/links',
    '/api/dropbox/list',
    '/api/dropbox/files',
    '/api/dropbox/photos',
    '/api/get-photos',
    '/api/get-images',
    '/api/get-gallery',
    '/api/client',
    '/api/clients',
]
for p in api_paths:
    code, body, hdrs = fetch(base + p)
    if code != 404:
        print(f"  GET {p} => {code}: {body[:300]}", flush=True)
    code2, body2, hdrs2 = fetch(base + p, method='POST',
        data=b'{}', headers={'Content-Type': 'application/json'})
    if code2 != 404:
        print(f"  POST {p} => {code2}: {body2[:300]}", flush=True)

# 5. Look at the gallery page JS chunks specifically
print("\n\n=== GALLERY PAGE JS ANALYSIS ===", flush=True)
# Get login page too - look for form action, API endpoints
code, body, hdrs = fetch(base + '/login')
print(f"Login page status: {code}, size: {len(body)}", flush=True)
# Search for form actions, fetch calls, api URLs
for pattern in [r'action=["\']([^"\']+)', r'fetch\(["\']([^"\']+)', r'/api/[a-zA-Z0-9/_-]+', r'dropbox', r'dbx', r'https://[^"\'\\s]+']:
    matches = re.findall(pattern, body, re.IGNORECASE)
    if matches:
        print(f"  Login page [{pattern}]: {matches[:5]}", flush=True)

# 6. Check headers for interesting info
print("\n\n=== RESPONSE HEADERS ===", flush=True)
code, body, hdrs = fetch(base + '/')
for k, v in hdrs.items():
    print(f"  {k}: {v}", flush=True)

print("\nDONE", flush=True)
