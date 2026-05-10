import asyncio
from concurrent.futures import ThreadPoolExecutor
try:
    from ddgs import DDGS
except ImportError:
    from duckduckgo_search import DDGS

_executor = ThreadPoolExecutor(max_workers=4)

class DorkingEngine:
    def __init__(self, target: str):
        self.target = target

    def _run_search(self, query: str) -> list[dict]:
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=20))
            return results
        except Exception:
            return []

    async def execute_dorks(self, dork_list: list[str]) -> dict:
        loop = asyncio.get_event_loop()
        all_findings = []

        for dork in dork_list:
            query = f"{dork} {self.target}"
            results = await loop.run_in_executor(_executor, self._run_search, query)
            for res in results:
                all_findings.append({
                    "dork_used": dork,
                    "title":   res.get("title"),
                    "link":    res.get("href"),
                    "snippet": res.get("body"),
                })

        unique_findings = list({f["link"]: f for f in all_findings if f["link"]}.values())

        return {
            "target":      self.target,
            "total_found": len(unique_findings),
            "findings":    unique_findings,
        }
