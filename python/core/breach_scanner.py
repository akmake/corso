import httpx
from typing import Dict, Any

class BreachScanner:
    """
    Checks if an email was involved in known data breaches using the free XposedOrNot API.
    """
    def __init__(self, email: str):
        self.email = email

    async def scan(self) -> Dict[str, Any]:
        results = {
            "email": self.email,
            "breached": False,
            "breaches": [],
        }
        
        try:
             async with httpx.AsyncClient(timeout=15) as client:
                 res = await client.get(f"https://api.xposedornot.com/v1/check-email/{self.email}")
                 if res.status_code == 200:
                     data = res.json()
                     breaches = data.get("breaches", [[]])[0] if data.get("breaches") else []
                     
                     if breaches:
                         results["breached"] = True
                         for breach_name in breaches:
                             results["breaches"].append({
                                 "name": breach_name,
                                 "source": "XposedOrNot",
                                 "risk": "High"
                             })
                 elif res.status_code == 404:
                     # 404 in this API means no breach found, which is good!
                     results["breached"] = False
                 else:
                     results["error"] = f"API returned HTTP {res.status_code}"

        except Exception as e:
            results["error"] = str(e)
            
        return results
