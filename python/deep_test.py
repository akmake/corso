import httpx, asyncio, re, json, sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

async def test():
    base = 'https://itzfoto.co.il'
    supabase = 'https://hfqdengmejmekljcexmm.supabase.co'

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20) as c:
        jr = await c.get(base + '/assets/index-JngCYylR.js')
        js = jr.text
        anon_key = re.findall(r'eyJ[a-zA-Z0-9_\-\.]{50,}', js)[0]
        headers = {'apikey': anon_key, 'Authorization': f'Bearer {anon_key}'}
        
        # 1. Find ALL dropbox-related context in JS
        print('=== DROPBOX CONTEXT IN JS ===')
        for pattern in ['dropbox-list-photos', 'dropbox-list-folders', 'dropbox-get-thumbnail', 
                        'dropbox-upload-file', 'dropbox_folder_path']:
            idx = js.find(pattern)
            if idx >= 0:
                start = max(0, idx - 200)
                end = min(len(js), idx + 200)
                snippet = js[start:end].replace('\n', ' ')
                print(f'\n[{pattern}]:\n  ...{snippet}...')
        
        # 2. These look like Supabase Edge Functions! Test them directly
        print('\n\n=== TESTING SUPABASE EDGE FUNCTIONS ===')
        edge_functions = [
            'dropbox-list-photos',
            'dropbox-list-folders', 
            'dropbox-get-thumbnail',
            'dropbox-upload-file',
        ]
        
        for func in edge_functions:
            url = f'{supabase}/functions/v1/{func}'
            
            # Try without auth
            print(f'\n--- {func} (no auth) ---')
            r = await c.post(url, json={})
            print(f'  POST no-auth: {r.status_code} - {r.text[:300]}')
            
            # Try with anon key
            print(f'--- {func} (anon key) ---')
            r = await c.post(url, json={}, headers=headers)
            print(f'  POST anon: {r.status_code} - {r.text[:300]}')
            
            # Try with folder param
            r = await c.post(url, json={'path': '/clients_photos/gol', 'folder': 'clients_photos/gol'}, headers=headers)
            print(f'  POST with folder: {r.status_code} - {r.text[:500]}')
        
        # 3. Test signup with a stronger password
        print('\n\n=== SIGNUP WITH STRONG PASSWORD ===')
        r = await c.post(f'{supabase}/auth/v1/signup', 
            json={'email': 'secaudit_test_xz9@protonmail.com', 'password': 'Xk9$mPq2vR!nLw'},
            headers=headers)
        print(f'Status: {r.status_code}')
        resp = r.text[:800]
        print(f'Response: {resp}')
        
        # If signup worked, try to use that session
        if r.status_code == 200:
            data = r.json()
            if 'access_token' in data:
                token = data['access_token']
                print(f'\nGot access token! Testing tables...')
                auth_headers = {'apikey': anon_key, 'Authorization': f'Bearer {token}'}
                for table in ['clients', 'client_photo_selections', 'user_roles']:
                    r2 = await c.get(f'{supabase}/rest/v1/{table}?select=*&limit=5', headers=auth_headers)
                    print(f'  {table}: {r2.status_code} - {r2.text[:300]}')
        
        # 4. Check the old /api/photos endpoint
        print('\n\n=== OLD API ENDPOINTS ===')
        old_endpoints = [
            ('/api/photos', 'POST', {'folder': 'clients_photos/gol', 'page': 1, 'limit': 20}),
            ('/api/login', 'POST', {'username': 'test', 'password': 'test'}),
            ('/api/save-selection', 'POST', {'folder': 'test', 'selection': {}}),
            ('/api/get-selection', 'POST', {'folder': 'test'}),
            ('/api/finalize', 'POST', {'username': 'test'}),
        ]
        for path, method, body in old_endpoints:
            r = await c.request(method, f'{base}{path}', json=body)
            print(f'  {method} {path}: {r.status_code} - {r.text[:200]}')
        
        # 5. Look for admin login flow
        print('\n\n=== ADMIN LOGIN FLOW ===')
        r = await c.get(f'{base}/admin-login')
        print(f'GET /admin-login: {r.status_code} ({len(r.text)} bytes)')
        r = await c.get(f'{base}/admin')
        print(f'GET /admin: {r.status_code} ({len(r.text)} bytes)')
        
        # 6. Find how auth works - search for signInWithPassword context
        print('\n\n=== AUTH FLOW IN JS ===')
        signin_idx = js.find('signInWithPassword')
        if signin_idx >= 0:
            start = max(0, signin_idx - 300)
            end = min(len(js), signin_idx + 300)
            print(f'signInWithPassword context:\n  {js[start:end]}')
        
        # Find what happens after login
        for pattern in ['onAuthStateChange', '/gallery', 'session', 'client_categories']:
            idxs = [m.start() for m in re.finditer(re.escape(pattern), js)]
            if idxs:
                idx = idxs[0]
                start = max(0, idx - 150)
                end = min(len(js), idx + 200)
                clean = js[start:end].replace('\n', ' ')
                print(f'\n[{pattern}] at pos {idx}:\n  ...{clean}...')

asyncio.run(test())
