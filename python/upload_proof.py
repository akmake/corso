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

    folder = "/clients_photos/פרצתי"

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=60) as c:
        for i, fpath in enumerate(files, 1):
            fname = os.path.basename(fpath)
            if not os.path.exists(fpath):
                print(f'[{i}/6] FILE NOT FOUND: {fpath}')
                continue

            size = os.path.getsize(fpath)
            print(f'[{i}/6] Reading {fname} ({size:,} bytes)...')

            with open(fpath, 'rb') as f:
                raw = f.read()

            b64 = base64.b64encode(raw).decode('ascii')

            print(f'  Uploading as base64 ({len(b64):,} chars)...')
            r = await c.post(upload_url, json={
                'path': f'{folder}/{fname}',
                'content': b64
            })
            print(f'  Result: {r.status_code} - {r.text[:200]}')

        print(f'\nDone! Check Dropbox folder: {folder}')

asyncio.run(upload())
