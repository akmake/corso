import urllib.request, ssl, re, sys

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

# Step 1: Get a JS chunk
print("Fetching chunk...", flush=True)
body = fetch(base + '/_next/static/chunks/0uatvedpciep6.js')
print(f"Got {len(body)} bytes", flush=True)
print(body[:2000], flush=True)
