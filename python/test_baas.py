"""Quick integration test: run baas_scanner against itzfoto.co.il"""
import asyncio, sys, json
sys.path.insert(0, '.')
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from core.baas_scanner import scan_baas

async def main():
    async def progress(msg):
        print(f"  >> {msg}")

    print("Running BaaS scanner on https://www.itzfoto.co.il ...\n")
    findings = await scan_baas("https://www.itzfoto.co.il", progress_cb=progress)

    print(f"\n{'='*60}")
    print(f"Total findings: {len(findings)}")
    print(f"{'='*60}\n")

    for f in findings:
        icon = {"critical":"!!!","high":"!! ","medium":"!  ","low":"~  ","info":"   "}.get(f.severity, "   ")
        print(f"[{icon}] [{f.severity.upper():8}] {f.title}")
        if f.description:
            print(f"    {f.description[:120]}")
        for e in f.evidence[:3]:
            if e:
                print(f"    > {e[:120]}")
        if f.recommendation:
            print(f"    FIX: {f.recommendation[:120]}")
        print()

    # Summary
    from collections import Counter
    c = Counter(f.severity for f in findings)
    print(f"Summary: critical={c.get('critical',0)} high={c.get('high',0)} medium={c.get('medium',0)} low={c.get('low',0)} info={c.get('info',0)}")

asyncio.run(main())
