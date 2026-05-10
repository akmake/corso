import urllib.request, urllib.error, ssl, re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

base = 'https://www.itzfoto.co.il'
ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

def fetch(path):
    req = urllib.request.Request(base + path, headers={'User-Agent': ua})
    try:
        resp = urllib.request.urlopen(req, context=ctx)
        return resp.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        print(f'{path} => HTTP {e.code}')
        return body

chunks = [
    '/_next/static/chunks/0uatvedpciep6.js',
    '/_next/static/chunks/0d3shmwh5_nmn.js',
    '/_next/static/chunks/0dgq26a5_oy.a.js',
    '/_next/static/chunks/0bogtdbh.dcu1.js',
    '/_next/static/chunks/0257pdz1-imal.js',
    '/_next/static/chunks/01xlw8hd842-c.js',
    '/_next/static/chunks/0ht900cau6_ur.js',
]

patterns = [
    ('dropbox', r'dropbox'),
    ('dbx', r'dbx'),
    ('api_key', r'api[_\-]?key'),
    ('api_secret', r'api[_\-]?secret'),
    ('token', r'token'),
    ('bearer', r'bearer'),
    ('refresh', r'refresh'),
    ('dropbox_token', r'sl\.[a-zA-Z0-9_\-]{20,}'),
    ('dl.dropboxusercontent', r'dropboxusercontent'),
    ('api_route', r'/api/'),
    ('gallery', r'gallery'),
    ('photos', r'photos'),
    ('images_path', r'images'),
    ('folder', r'folder'),
    ('password', r'password'),
    ('secret', r'secret'),
    ('NEXT_PUBLIC', r'NEXT_PUBLIC'),
    ('process_env', r'process\.env'),
    ('fetch_url', r'fetch\s*\('),
    ('axios', r'axios'),
    ('Authorization', r'[Aa]uthorization'),
]

for chunk in chunks:
    body = fetch(chunk)
    print(f'\n=== {chunk} ({len(body)} bytes) ===')
    
    for name, pat in patterns:
        matches = list(re.finditer(pat, body, re.IGNORECASE))
        if matches:
            seen = set()
            for m in matches[:5]:
                idx = m.start()
                start = max(0, idx - 100)
                end = min(len(body), idx + len(m.group()) + 100)
                snippet = body[start:end].replace('\n', ' ')
                if snippet not in seen:
                    seen.add(snippet)
                    print(f'  [{name}] ...{snippet}...')

# Now check login page and common API routes
print('\n\n=== CHECKING PAGES & API ROUTES ===')
pages = [
    '/login',
    '/gallery', 
    '/api/photos',
    '/api/gallery',
    '/api/images',
    '/api/folders',
    '/api/dropbox',
    '/api/auth/session',
    '/api/auth/providers',
    '/api/auth/csrf',
    '/api/user',
    '/api/users',
]

for p in pages:
    body = fetch(p)
    print(f'\n--- {p} ({len(body)} bytes) ---')
    if len(body) < 2000:
        print(body[:2000])
    else:
        # Search for sensitive stuff
        for name, pat in patterns:
            matches = list(re.finditer(pat, body, re.IGNORECASE))
            if matches:
                for m in matches[:3]:
                    idx = m.start()
                    start = max(0, idx - 60)
                    end = min(len(body), idx + len(m.group()) + 60)
                    print(f'  [{name}] ...{body[start:end]}...')
