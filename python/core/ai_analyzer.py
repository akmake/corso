# python/core/ai_analyzer.py

import asyncio
import logging
import httpx
import json
import os
from typing import Dict, Any, List

log = logging.getLogger("AIAnalyst")
log.setLevel(logging.INFO)

class VulnerabilityAIAnalyst:
    """
    מודול אינטליגנציה מלאכותית לניתוח שגיאות שרת והצעת פיילודים בזמן אמת.
    משתמש ב-OpenAI API כדי לקבל החלטות סייבר.
    """
    def __init__(self, api_key: str = None, model: str = "gpt-4o"):
        # מושך מפתח מהסביבה אם לא סופק ישירות
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model
        self.api_url = "https://api.openai.com/v1/chat/completions"

        if not self.api_key:
            log.warning("⚠️ לא סופק OPENAI_API_KEY! מודול ה-AI לא יפעל כראוי.")

        # פרומפט המערכת (System Prompt) שמגדיר ל-AI את התפקיד שלו
        self.system_prompt = """
        You are an elite offensive cybersecurity expert and penetration tester.
        Your job is to analyze HTTP responses, server errors, and app behavior to identify vulnerabilities (especially in BaaS, Supabase, Firebase, and AI-generated apps).
        You must ALWAYS respond in valid JSON format ONLY. 
        Do not include markdown blocks like ```json. Just return the raw JSON object.
        """

    async def analyze_server_anomaly(self, status_code: int, response_body: str, target_endpoint: str) -> Dict[str, Any]:
        """
        מקבל שגיאה לא ברורה מהשרת ומנתח האם מדובר בהדלפת מידע או חולשה, ומציע צעד הבא.
        """
        if not self.api_key:
            return {"error": "No API Key configured"}

        log.info(f"🧠 מפעיל את מודל {self.model} לניתוח אנומליה ב- {target_endpoint} (Status: {status_code})")

        # אנו מגבילים את אורך גוף התגובה כדי לא לחרוג מלימיט הטוקנים של ה-LLM
        truncated_body = response_body[:1500] 

        prompt = f"""
        Analyze the following server response from an automated pentest.
        
        Target Endpoint: {target_endpoint}
        HTTP Status: {status_code}
        Response Body snippet:
        {truncated_body}

        Determine if this response indicates a potential vulnerability (e.g., SQLi, Stack Trace leak, RLS bypass, Bad validation).
        Return a JSON with the following structure:
        {{
            "is_vulnerable": boolean,
            "vulnerability_type": "string (or null)",
            "confidence_score": 1-100,
            "analysis": "Brief explanation of what the server is leaking/doing",
            "suggested_next_payloads": ["payload1", "payload2"]
        }}
        """

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    self.api_url,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": self.system_prompt},
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0.2, # טמפרטורה נמוכה לתשובות מדויקות ואנליטיות
                        "response_format": {"type": "json_object"} # מכריח את OpenAI להחזיר JSON תקין
                    }
                )

            if response.status_code == 200:
                result_json = response.json()
                ai_content = result_json["choices"][0]["message"]["content"]
                
                # המרת הטקסט שחזר מה-AI לאובייקט מילון בפייתון
                analysis_data = json.loads(ai_content)
                log.info(f"💡 מסקנת AI: החולשה {analysis_data.get('vulnerability_type', 'None')} (ביטחון: {analysis_data.get('confidence_score')}%)")
                return analysis_data
            else:
                log.error(f"שגיאה מ-OpenAI: {response.text}")
                return {"error": "API Request failed"}

        except Exception as e:
            log.error(f"שגיאה בניתוח AI: {e}")
            return {"error": str(e)}

# ==========================================
# הרצה לבדיקה עצמאית של המודול
# ==========================================
if __name__ == "__main__":
    # זיוף של שגיאת שרת אופיינית לאתרי AI גרועים (חושף את ה-Postgres)
    fake_500_response = """
    {"error": "Internal Server Error", "message": "operator does not exist: uuid = character varying", 
    "hint": "No operator matches the given name and argument types. You might need to add explicit type casts.",
    "position": "120", "query": "SELECT * FROM public.users WHERE id = 'admin' OR 1=1"}
    """
    
    # ודא שיש לך מפתח סביבה פתוח בטרמינל:
    # export OPENAI_API_KEY="sk-proj-...." (בלינוקס/מק)
    # set OPENAI_API_KEY="sk-proj-...." (בווינדוס)
    
    analyst = VulnerabilityAIAnalyst()
    
    # הרצת האנליזה
    result = asyncio.run(analyst.analyze_server_anomaly(
        status_code=500, 
        response_body=fake_500_response, 
        target_endpoint="/api/v1/users?id=admin' OR 1=1--"
    ))
    
    print("\n--- החלטת הסוכן המלאכותי ---")
    print(json.dumps(result, indent=2, ensure_ascii=False))