import asyncio, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from core.baas_scanner import scan_baas

async def main():
    print("=" * 60)
    print("BaaS Scanner - ziporiteem.com")
    print("=" * 60)
    findings = await scan_baas("https://ziporiteem.com/")
    print(f"\nTOTAL FINDINGS: {len(findings)}")
    print("-" * 60)
    for i, f in enumerate(findings, 1):
        sev = f.severity.upper()
        icon = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  ", "LOW": ".  ", "INFO": "   "}.get(sev, "   ")
        print(f"\n[{icon}] [{sev:8s}] {f.title}")
        if f.description:
            print(f"    {f.description[:200]}")
        if f.evidence:
            for e in f.evidence[:3]:
                if e:
                    print(f"    > {e[:180]}")
        if f.recommendation:
            print(f"    FIX: {f.recommendation[:180]}")

    crits = sum(1 for f in findings if f.severity == "critical")
    highs = sum(1 for f in findings if f.severity == "high")
    meds = sum(1 for f in findings if f.severity == "medium")
    infos = sum(1 for f in findings if f.severity == "info")
    print(f"\n{'=' * 60}")
    print(f"Summary: {crits} critical, {highs} high, {meds} medium, {infos} info")
    print(f"{'=' * 60}")

asyncio.run(main())
