import urllib.request, ssl, re

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def fetch(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=15)
        return resp.read().decode('utf-8', errors='replace')
    except Exception as e:
        return f'ERROR: {e}'

base = 'https://www.itzfoto.co.il'

chunks = [
    '/_next/static/chunks/0uatvedpciep6.js',
    '/_next/static/chunks/0d3shmwh5_nmn.js',
    '/_next/static/chunks/0dgq26a5_oy.a.js',
    '/_next/static/chunks/0bogtdbh.dcu1.js',
    '/_next/static/chunks/0257pdz1-imal.js',
    '/_next/static/chunks/01xlw8hd842-c.js',
    '/_next/static/chunks/0ht900cau6_ur.js',
]

pages = [
    '/login', '/gallery', '/api/photos', '/api/gallery', '/api/images',
    '/api/folders', '/api/dropbox', '/api/auth/session', '/api/auth/providers',
    '/api/auth/csrf', '/api/user', '/api/users',
]

keywords = ['dropbox', 'dbx', 'token', 'api_key', 'api_secret', 'bearer',
            'authorization', 'sl.', 'dropboxusercontent', 'gallery', 'folder',
            'password', 'secret', 'NEXT_PUBLIC', 'process.env', 'fetch(', 
            '/api/', 'photos', 'images']

with open('scan_results.txt', 'w', encoding='utf-8') as f:
    for chunk in chunks:
        body = fetch(base + chunk)
        f.write(f'\n=== {chunk} ({len(body)} bytes) ===\n')
        for kw in keywords:
            if kw.lower() in body.lower():
                idx = body.lower().find(kw.lower())
                snippet = body[max(0,idx-120):idx+len(kw)+120]
                f.write(f'  FOUND [{kw}]: ...{snippet}...\n')
                # Find all occurrences
                count = body.lower().count(kw.lower())
                if count > 1:
                    f.write(f'    ({count} total occurrences)\n')
    
    for page in pages:
        body = fetch(base + page)
        f.write(f'\n--- {page} ({len(body)} bytes) ---\n')
        if len(body) < 500:
            f.write(body + '\n')
        else:
            for kw in keywords:
                if kw.lower() in body.lower():
                    idx = body.lower().find(kw.lower())
                    snippet = body[max(0,idx-80):idx+len(kw)+80]
                    f.write(f'  FOUND [{kw}]: ...{snippet}...\n')

    # Also try to find _next/data paths (SSR data)
    f.write('\n\n=== TRYING _NEXT/DATA PATHS ===\n')
    build_id = 'jcxNddl9utkjILSbuDX2B'
    data_paths = [
        f'/_next/data/{build_id}/index.json',
        f'/_next/data/{build_id}/login.json',
        f'/_next/data/{build_id}/gallery.json',
        f'/_next/data/{build_id}/dashboard.json',
    ]
    for dp in data_paths:
        body = fetch(base + dp)
        f.write(f'\n--- {dp} ---\n')
        f.write(body[:1000] + '\n')

print('DONE - results in scan_results.txt')
