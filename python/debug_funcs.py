import httpx, asyncio, re, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
async def main():
    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20) as c:
        r = await c.get('https://itzfoto.co.il')
        html = r.text
        js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html)
        print('JS URLs:', js_urls)
        all_js = ''
        for url in js_urls:
            if url.startswith('/'):
                url = 'https://itzfoto.co.il' + url
            resp = await c.get(url)
            all_js += resp.text
        print(f'Total JS: {len(all_js)} chars')
        funcs = re.findall(r'functions/v1/([a-zA-Z0-9_\-]+)', all_js)
        print('Functions found:', sorted(set(funcs)))
        # broader search
        dropbox = re.findall(r'dropbox[\w\-]*', all_js, re.I)
        print('Dropbox refs:', sorted(set(dropbox)))
        # search for function invocation patterns
        invoke = re.findall(r'\.invoke\(["\']([^"\']+)["\']', all_js)
        print('Invoke calls:', sorted(set(invoke)))
asyncio.run(main())
