"""Deep analysis of ziporiteem.com technology stack and security."""
import httpx, sys, re, json
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def main():
    c = httpx.Client(follow_redirects=True, verify=False, timeout=20)
    
    # 1. Get HTML
    r = c.get('https://ziporiteem.com/')
    html = r.text
    print(f"=== HTML Analysis ===")
    print(f"Server: {r.headers.get('server', 'N/A')}")
    print(f"Headers: {dict(r.headers)}")
    
    # 2. Find all JS/CSS files
    js_files = re.findall(r'(?:src|href)=["\']([^"\']*\.(?:js|css))["\']', html)
    print(f"\n=== Asset files: {len(js_files)} ===")
    for f in js_files:
        print(f"  {f}")
    
    # 3. Download and analyze each JS file
    all_js = ""
    for js_path in js_files:
        if not js_path.endswith('.js'):
            continue
        url = f"https://ziporiteem.com{js_path}" if js_path.startswith('/') else js_path
        try:
            r = c.get(url)
            print(f"\n  {js_path}: {len(r.text):,} chars")
            all_js += r.text
        except Exception as e:
            print(f"  {js_path}: ERROR {e}")
    
    print(f"\n=== Total JS: {len(all_js):,} chars ===")
    
    # 4. Search for backend indicators
    patterns = {
        'Supabase URL': r'https://[a-z0-9]+\.supabase\.co',
        'Firebase URL': r'firebase[a-zA-Z]*\.googleapis\.com|firebaseapp\.com',
        'Firebase Config': r'apiKey.*?authDomain.*?projectId',
        'JWT Token': r'eyJ[A-Za-z0-9_-]{20,}',
        'API base URL': r'(?:baseURL|apiUrl|API_URL|base_url|api_base|BACKEND|backend)\s*[:=]\s*["\'][^"\']+',
        'fetch/axios calls': r'(?:fetch|axios|httpClient|apiClient)\s*[.(]["\'](?:https?://[^"\']+)',
        'Environment vars': r'(?:VITE_|REACT_APP_|NEXT_PUBLIC_|import\.meta\.env\.)[A-Z_]+',
        'API endpoints': r'["\']\/api\/[^"\']+["\']',
        'Auth patterns': r'(?:login|signup|register|authenticate|auth)\s*[:=(]',
        'Database patterns': r'(?:prisma|mongoose|sequelize|knex|drizzle|supabase|firebase)',
        'Payment': r'(?:stripe|paypal|paddle|lemonsqueezy)',
        'Websocket': r'(?:wss?://|socket\.io|websocket)',
        'GraphQL': r'(?:graphql|gql|mutation|query\s*\{)',
        'REST endpoints': r'(?:GET|POST|PUT|DELETE|PATCH)\s*["\'][^"\']+',
        'Any https URL': r'https://[a-zA-Z0-9._-]+\.[a-z]{2,}[/\w.-]*',
    }
    
    for name, pat in patterns.items():
        try:
            matches = list(set(re.findall(pat, all_js, re.IGNORECASE)))
            if matches:
                print(f"\n[FOUND] {name}: ({len(matches)} matches)")
                for m in sorted(matches)[:15]:
                    print(f"  {str(m)[:200]}")
        except Exception as e:
            print(f"\n[ERROR] {name}: {e}")

    # 5. Look for interesting strings near common keywords
    for keyword in ['token', 'secret', 'password', 'admin', 'role', 'auth']:
        positions = [m.start() for m in re.finditer(keyword, all_js, re.IGNORECASE)]
        if positions:
            print(f"\n[CONTEXT] '{keyword}' found {len(positions)} times. Samples:")
            for pos in positions[:3]:
                snippet = all_js[max(0,pos-40):pos+60].replace('\n',' ')
                print(f"  ...{snippet}...")

import io, contextlib
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    main()
output = buf.getvalue()
with open("ziporiteem_analysis.txt", "w", encoding="utf-8") as f:
    f.write(output)
print(f"Saved {len(output)} chars to ziporiteem_analysis.txt")
