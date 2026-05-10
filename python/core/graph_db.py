import os
import re

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "admin123456")

# Sanitize identifiers: keep only alphanumeric + underscore, convert to UPPER_SNAKE_CASE
def _sanitize_identifier(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9_]', '_', name).upper()


class OsintGraphDatabase:
    def __init__(self):
        try:
            from neo4j import GraphDatabase
            self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
            self.available = True
        except Exception:
            self.driver = None
            self.available = False

    def close(self):
        if self.driver:
            self.driver.close()

    def create_entity(self, label: str, entity_id: str, properties: dict = None):
        """יצירת צומת בגרף (למשל: Domain, Email, IP)"""
        if not self.available:
            return
        safe_label = _sanitize_identifier(label)
        props = properties or {}
        props["id"] = entity_id
        # Label is embedded via f-string (Cypher doesn't support parameterised labels)
        query = f"""
        MERGE (n:{safe_label} {{id: $entity_id}})
        SET n += $props
        RETURN n
        """
        with self.driver.session() as session:
            session.run(query, entity_id=entity_id, props=props)

    def create_relationship(self, label1: str, id1: str, rel_type: str, label2: str, id2: str):
        """יצירת קשר בין שני צמתים (למשל: Domain -> HAS_IP -> IP)"""
        if not self.available:
            return
        # Cypher cannot accept node labels or relationship types as runtime parameters —
        # they must be embedded in the query string. Sanitise to prevent injection.
        safe_l1  = _sanitize_identifier(label1)
        safe_l2  = _sanitize_identifier(label2)
        safe_rel = _sanitize_identifier(rel_type)
        query = f"""
        MATCH (a:{safe_l1} {{id: $id1}})
        MATCH (b:{safe_l2} {{id: $id2}})
        MERGE (a)-[r:{safe_rel}]->(b)
        RETURN r
        """
        with self.driver.session() as session:
            session.run(query, id1=id1, id2=id2)
            
# דוגמה לשימוש במנוע הקורלציה:
# db = OsintGraphDatabase()
# db.create_entity("Domain", "example.com", {"registrar": "GoDaddy"})
# db.create_entity("IP", "1.1.1.1")
# db.create_relationship("Domain", "example.com", "RESOLVES_TO", "IP", "1.1.1.1")