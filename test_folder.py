import urllib.request, ssl, json

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

base = 'https://www.itzfoto.co.il/api/photos'
folders = [
    'clintes_photo/gol',
    '/clintes_photo/gol',
    'clintes_photo/gol/',
    '/clintes_photo/gol/',
    'clintes_photos/gol',
    '/clintes_photos/gol',
    'clients_photo/gol',
    '/clients_photo/gol',
    'clients_photos/gol',
    '/clients_photos/gol',
    'gol',
    '/gol',
]

for folder in folders:
    data = json.dumps({'folder': folder, 'page': 1, 'limit': 20}).encode()
    req = urllib.request.Request(base, data=data,
        headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'},
        method='POST')
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=15)
        body = resp.read().decode('utf-8', errors='replace')
        print(f'[{resp.getcode()}] folder="{folder}" => {body[:500]}')
    except Exception as e:
        if hasattr(e, 'read'):
            body = e.read().decode('utf-8', errors='replace')
            print(f'[{e.code}] folder="{folder}" => {body[:200]}')
        else:
            print(f'[ERR] folder="{folder}" => {e}')
