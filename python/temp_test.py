import httpx, asyncio, re, json, sys, base64

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

async def test():
    base = 'https://itzfoto.co.il'
    supabase = 'https://hfqdengmejmekljcexmm.supabase.co'

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as c:
        jr = await c.get(base + '/assets/index-JngCYylR.js')
        js = jr.text
        anon_key = re.findall(r'eyJ[a-zA-Z0-9_\-\.]{50,}', js)[0]
        
        # Decode the JWT
        parts = anon_key.split('.')
        payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
        decoded = base64.b64decode(payload)
        print('=== ANON KEY DECODED ===')
        print(json.dumps(json.loads(decoded), indent=2))
        
        headers = {'apikey': anon_key, 'Authorization': f'Bearer {anon_key}'}
        
        # 1. Test signup
        print('\n=== TEST: SIGNUP ===')
        signup_data = {'email': 'test_security_audit_xyz@example.com', 'password': 'TestPass123!'}
        r = await c.post(f'{supabase}/auth/v1/signup', json=signup_data, headers=headers)
        print(f'Signup: {r.status_code} - {r.text[:500]}')
        
        # 2. Storage buckets
        print('\n=== STORAGE BUCKETS ===')
        r = await c.get(f'{supabase}/storage/v1/bucket', headers=headers)
        print(f'Buckets: {r.status_code} - {r.text[:500]}')
        
        buckets = ['photos', 'images', 'gallery', 'clients', 'uploads', 'public', 'avatars']
        for b in buckets:
            r = await c.post(f'{supabase}/storage/v1/object/list/{b}', 
                json={'prefix': '', 'limit': 10}, headers=headers)
            if r.status_code != 400 and r.status_code != 404:
                print(f'  Bucket [{b}]: {r.status_code} - {r.text[:300]}')
        
        # 3. /api/broadcast
        print('\n=== /api/broadcast ===')
        r = await c.get(f'{base}/api/broadcast')
        print(f'GET: {r.status_code} - CT: {r.headers.get("content-type","")} - {r.text[:300]}')
        r = await c.post(f'{base}/api/broadcast', json={})
        print(f'POST: {r.status_code} - {r.text[:300]}')
        
        # 4. RPC functions
        print('\n=== RPC FUNCTIONS ===')
        rpc_names = ['get_photos', 'get_clients', 'get_gallery', 'list_photos',
                     'get_user_data', 'authenticate', 'get_selections']
        for rpc in rpc_names:
            r = await c.post(f'{supabase}/rest/v1/rpc/{rpc}', json={}, headers=headers)
            if r.status_code != 404:
                print(f'  RPC {rpc}: {r.status_code} - {r.text[:200]}')
        
        # 5. RLS count test
        print('\n=== RLS COUNT TEST ===')
        for table in ['clients', 'client_photo_selections', 'client_categories', 'user_roles']:
            h = {**headers, 'Prefer': 'count=exact'}
            r = await c.get(f'{supabase}/rest/v1/{table}?select=*', headers=h)
            count = r.headers.get('content-range', 'N/A')
            print(f'  {table}: range={count}')
        
        # 6. JS deep analysis
        print('\n=== JS DEEP ANALYSIS ===')
        from_calls = re.findall(r'\.from\(["\']([^"\']+)["\']\)', js)
        print(f'All .from() tables: {sorted(set(from_calls))}')
        
        signin = re.findall(r'sign(?:In|Up|Out)[a-zA-Z]*\(', js)
        print(f'Sign patterns: {sorted(set(signin))}')
        
        roles = re.findall(r'role["\'\s:=]+["\']?([a-zA-Z_]+)', js[:100000])
        print(f'Roles: {sorted(set(roles))}')
        
        dropbox = re.findall(r'dropbox[a-zA-Z./:_\-]*', js, re.IGNORECASE)
        if dropbox:
            print(f'Dropbox refs: {sorted(set(dropbox))}')
        
        # Look for admin login/route logic
        admin_ctx = []
        for m in re.finditer(r'admin', js, re.IGNORECASE):
            start = max(0, m.start() - 100)
            end = min(len(js), m.end() + 100)
            admin_ctx.append(js[start:end])
        print(f'\nAdmin context snippets ({len(admin_ctx)} found):')
        for i, ctx in enumerate(admin_ctx[:10]):
            clean = ctx.replace('\n', ' ')
            print(f'  [{i}] ...{clean}...')

asyncio.run(test())
