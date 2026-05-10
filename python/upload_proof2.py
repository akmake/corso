import httpx, asyncio, sys, base64, os

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

async def upload():
    supabase = 'https://hfqdengmejmekljcexmm.supabase.co'
    upload_url = f'{supabase}/functions/v1/dropbox-upload-file'

    files = [
        r"C:\Users\yosef dahan\Pictures\Screenshots\צילום מסך 2026-04-07 004018.png",
        r"C:\Users\yosef dahan\Pictures\Screenshots\צילום מסך 2026-04-07 004554.png",
        r"C:\Users\yosef dahan\Pictures\Screenshots\צילום מסך 2026-04-07 004323.png",
        r"C:\Users\yosef dahan\Pictures\Screenshots\צילום מסך 2026-04-07 004211.png",
        r"C:\Users\yosef dahan\Pictures\Screenshots\צילום מסך 2026-04-07 004114.png",
        r"C:\Users\yosef dahan\Pictures\Screenshots\צילום מסך 2026-04-07 003335.png",
    ]

    # ASCII folder name to avoid header encoding issues
    folder = "/clients_photos/HACKED_proof"

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=60) as c:
        
        # First: test if the issue is Hebrew path or base64 content
        print('=== Debug: small base64 with ASCII path ===')
        import struct, zlib
        # tiny PNG
        sig = b'\x89PNG\r\n\x1a\n'
        def chunk(ct, d):
            ch = ct + d
            crc = struct.pack('>I', zlib.crc32(ch) & 0xffffffff)
            return struct.pack('>I', len(d)) + ch + crc
        ihdr = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
        raw = b'\x00\xff\x00\x00'
        idat = zlib.compress(raw)
        tiny_png = sig + chunk(b'IHDR', ihdr) + chunk(b'IDAT', idat) + chunk(b'IEND', b'')
        
        b64_tiny = base64.b64encode(tiny_png).decode()
        r = await c.post(upload_url, json={
            'path': f'{folder}/tiny_test.png',
            'content': b64_tiny
        })
        print(f'Tiny PNG base64 + ASCII path: {r.status_code} - {r.text[:200]}')
        
        # Test: Hebrew path with small content
        r = await c.post(upload_url, json={
            'path': '/clients_photos/פרצתי/test.txt',
            'content': 'hello'
        })
        print(f'Text + Hebrew path: {r.status_code} - {r.text[:200]}')
        
        # Test: ASCII path with real file base64
        print('\n=== Upload real screenshots ===')
        for i, fpath in enumerate(files, 1):
            fname = f'screenshot_{i}.png'  # ASCII filename
            if not os.path.exists(fpath):
                print(f'[{i}/6] NOT FOUND: {fpath}')
                continue

            size = os.path.getsize(fpath)
            with open(fpath, 'rb') as f:
                raw_bytes = f.read()
            
            b64 = base64.b64encode(raw_bytes).decode('ascii')
            print(f'[{i}/6] {os.path.basename(fpath)} ({size:,}B, b64={len(b64):,})...')
            
            r = await c.post(upload_url, json={
                'path': f'{folder}/{fname}',
                'content': b64
            })
            print(f'  -> {r.status_code} - {r.text[:200]}')

        print(f'\nFiles to delete: {folder}/')

asyncio.run(upload())
