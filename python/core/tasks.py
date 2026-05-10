import asyncio
from core.celery_app import app
from core.dorking_engine import DorkingEngine
from core.scraper_playwright import PlaywrightExtractor
from core.graph_db import OsintGraphDatabase

@app.task(bind=True)
def run_deep_domain_investigation(self, domain: str):
    """משימת Celery מלאה שמבצעת חקירה ושומרת לגרף"""
    self.update_state(state='PROGRESS', meta={'status': 'Starting Dorking phase...'})
    
    # בגלל ש-Celery לא אסינכרוני מטבעו, ניצור loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # 1. Dorking
    dork_engine = DorkingEngine(domain)
    dork_results = loop.run_until_complete(
        dork_engine.execute_dorks(['site:', 'filetype:pdf OR filetype:xls', 'intitle:"index of"'])
    )
    
    # 2. Playwright Scraping
    self.update_state(state='PROGRESS', meta={'status': 'Extracting dynamic data via Headless Browser...'})
    scraper = PlaywrightExtractor(domain)
    scrape_results = loop.run_until_complete(scraper.extract_deep_data())
    
    # 3. הכנסה למסד הנתונים הגרפי (Neo4j)
    self.update_state(state='PROGRESS', meta={'status': 'Building relationships in Graph DB...'})
    graph = OsintGraphDatabase()
    
    # יצירת הצומת הראשי
    graph.create_entity("Domain", domain, {"title": scrape_results.get("title", "")})
    
    # חיבור אימיילים שנמצאו לגרף
    for email in scrape_results.get("emails_found", []):
        graph.create_entity("Email", email)
        graph.create_relationship("Domain", domain, "CONTAINS_EMAIL", "Email", email)
        
    graph.close()
    
    return {
        "status": "completed",
        "domain": domain,
        "dorks_hits": dork_results.get("total_found", 0),
        "dorks_data": dork_results.get("findings", []),
        "emails_extracted": scrape_results.get("emails_found", []),
        "phones_found": scrape_results.get("phones_found", []),
        "title": scrape_results.get("title", ""),
    }