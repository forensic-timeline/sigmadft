# src/graph2web/app.py

"""graph2web backend: read-only JSON API over the log2graph Neo4j databases.

Every Neo4j session is opened with READ access, so the web app can never
modify a database, and only databases named 'sigmadft-*' are reachable
(same rule as log2graph, shared through log2graph.config).
"""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from neo4j import READ_ACCESS, GraphDatabase
from neo4j.exceptions import Neo4jError
from neo4j.graph import Node, Path as GraphPath, Relationship
from pydantic import BaseModel

from log2graph import config

STATIC_DIR = Path(__file__).parent / "static"
MAX_CYPHER_ROWS = 5000

_driver = None


def driver():
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(config.NEO4J_URI,
                                       auth=(config.NEO4J_USER, config.NEO4J_PASSWORD))
    return _driver


@asynccontextmanager
async def lifespan(_app):
    yield
    if _driver is not None:
        _driver.close()


app = FastAPI(title="graph2web", docs_url="/api/docs", openapi_url="/api/openapi.json",
              lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def _session(database: str):
    try:
        config.check_database_name(database)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))
    return driver().session(database=database, default_access_mode=READ_ACCESS)


def _value(value: Any) -> Any:
    """Neo4j values -> JSON (temporal types as ISO strings)."""
    if isinstance(value, (list, tuple)):
        return [_value(v) for v in value]
    if isinstance(value, dict):
        return {k: _value(v) for k, v in value.items()}
    if hasattr(value, "iso_format"):
        return value.iso_format()
    return value


def _node(node: Node) -> Dict[str, Any]:
    return {"id": node.element_id, "labels": sorted(node.labels),
            "props": {k: _value(v) for k, v in node.items()}}


def _edge(rel: Relationship) -> Dict[str, Any]:
    return {"id": rel.element_id, "type": rel.type,
            "source": rel.start_node.element_id, "target": rel.end_node.element_id,
            "props": {k: _value(v) for k, v in rel.items()}}


class _Collector:
    """Collect graph objects found anywhere in Cypher results."""

    def __init__(self):
        self.nodes: Dict[str, Dict] = {}
        self.edges: Dict[str, Dict] = {}

    def add(self, value: Any) -> Any:
        if isinstance(value, Node):
            self.nodes.setdefault(value.element_id, _node(value))
            return {"node": value.element_id}
        if isinstance(value, Relationship):
            for end in (value.start_node, value.end_node):
                if end is not None and end.element_id not in self.nodes:
                    self.nodes[end.element_id] = _node(end)
            self.edges.setdefault(value.element_id, _edge(value))
            return {"relationship": value.element_id, "type": value.type}
        if isinstance(value, GraphPath):
            for n in value.nodes:
                self.add(n)
            for r in value.relationships:
                self.add(r)
            return {"path": len(value.relationships)}
        if isinstance(value, (list, tuple)):
            return [self.add(v) for v in value]
        if isinstance(value, dict):
            return {k: self.add(v) for k, v in value.items()}
        return _value(value)


# ----------------------------------------------------------------------
# API
# ----------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/databases")
def databases() -> List[str]:
    """Online databases with the project prefix only."""
    with driver().session(database="system", default_access_mode=READ_ACCESS) as s:
        names = [r["name"] for r in s.run(
            "SHOW DATABASES YIELD name, currentStatus "
            "WHERE currentStatus = 'online' RETURN DISTINCT name ORDER BY name")]
    return [n for n in names if n.startswith(config.DATABASE_PREFIX)]


@app.get("/api/stats")
def stats(db: str = Query(...)) -> Dict[str, Any]:
    with _session(db) as s:
        labels = {r["l"]: r["c"] for r in s.run(
            "MATCH (n) UNWIND labels(n) AS l RETURN l, count(*) AS c ORDER BY c DESC")}
        types = {r["t"]: r["c"] for r in s.run(
            "MATCH ()-[r]->() RETURN type(r) AS t, count(*) AS c ORDER BY c DESC")}
    return {"labels": labels, "relationships": types}


@app.get("/api/graph")
def graph(db: str = Query(...)) -> Dict[str, Any]:
    """Every node and relationship of the database (no display limit)."""
    with _session(db) as s:
        nodes = [{"id": r["id"], "labels": sorted(r["labels"]),
                  "props": {k: _value(v) for k, v in r["props"].items()}}
                 for r in s.run("MATCH (n) RETURN elementId(n) AS id, labels(n) AS labels, "
                                "properties(n) AS props")]
        edges = [{"id": r["id"], "type": r["type"], "source": r["s"], "target": r["t"],
                  "props": {k: _value(v) for k, v in r["props"].items()}}
                 for r in s.run("MATCH (a)-[r]->(b) RETURN elementId(r) AS id, type(r) AS type, "
                                "elementId(a) AS s, elementId(b) AS t, properties(r) AS props")]
    return {"nodes": nodes, "edges": edges}


class CypherRequest(BaseModel):
    db: str
    query: str
    params: Optional[Dict[str, Any]] = None


@app.post("/api/cypher")
def cypher(req: CypherRequest) -> Dict[str, Any]:
    """Run a READ-ONLY Cypher query; returns table rows + the graph objects in them."""
    collector = _Collector()
    rows, truncated = [], False
    try:
        with _session(req.db) as s:
            result = s.run(req.query, req.params or {})
            columns = list(result.keys())
            for i, record in enumerate(result):
                if i >= MAX_CYPHER_ROWS:
                    truncated = True
                    break
                rows.append([collector.add(v) for v in record.values()])
    except Neo4jError as e:
        raise HTTPException(status_code=400, detail=f"{e.code}: {e.message}")
    return {"columns": columns, "rows": rows, "truncated": truncated,
            "nodes": list(collector.nodes.values()), "edges": list(collector.edges.values())}
