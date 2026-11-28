# src/graph2web/app.py

"""graph2web backend: JSON API over the log2graph Neo4j databases.

Browsing (graph, stats, Cypher) opens every Neo4j session with READ access,
so a query from the UI can never modify a database. Writing happens only in
the case pipeline (cases.py: upload + import, anomaly detection, event
reconstruction), whose endpoints accept requests from this machine only.
Only databases named 'sigmadft-*' are reachable (same rule as log2graph,
shared through log2graph.config).
"""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from neo4j import READ_ACCESS, GraphDatabase
from neo4j.exceptions import AuthError, DriverError, Neo4jError, ServiceUnavailable
from neo4j.graph import Node, Path as GraphPath, Relationship
from pydantic import BaseModel

from graph2web.cases import CaseError, Cases, get_job
from log2graph import config

STATIC_DIR = Path(__file__).parent / "static"
MAX_CYPHER_ROWS = 5000

_driver = None
# Connection used by the web app. Starts from log2graph.config (env vars) and can be
# changed from the Settings > Database dialog; changes last until the server restarts.
_conn = {"uri": config.NEO4J_URI, "user": config.NEO4J_USER, "password": config.NEO4J_PASSWORD}


def driver():
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(_conn["uri"], auth=(_conn["user"], _conn["password"]))
    return _driver


cases = Cases(lambda: dict(_conn), driver)


@asynccontextmanager
async def lifespan(_app):
    yield
    if _driver is not None:
        _driver.close()


app = FastAPI(title="SigmaDFT", docs_url="/api/docs", openapi_url="/api/openapi.json",
              lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def revalidate_frontend(request, call_next):
    """Make the browser revalidate the page and static files (ETag -> 304), so
    edits to app.js/style.css show up on a normal reload instead of a stale cache."""
    response = await call_next(request)
    if not request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


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


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    """Browsers that ask for /favicon.ico directly get the SVG icon."""
    return FileResponse(STATIC_DIR / "favicon.svg", media_type="image/svg+xml")


@app.get("/api/databases")
def databases() -> List[str]:
    """Online databases with the project prefix only."""
    try:
        return _list_databases(driver())
    except (DriverError, Neo4jError, ValueError) as e:
        raise HTTPException(status_code=503, detail=f"Cannot connect to Neo4j at {_conn['uri']}: {_error_text(e)}")


def _list_databases(drv) -> List[str]:
    with drv.session(database="system", default_access_mode=READ_ACCESS) as s:
        names = [r["name"] for r in s.run(
            "SHOW DATABASES YIELD name, currentStatus "
            "WHERE currentStatus = 'online' RETURN DISTINCT name ORDER BY name")]
    return [n for n in names if n.startswith(config.DATABASE_PREFIX)]


def _error_text(e: Exception) -> str:
    if isinstance(e, AuthError):
        return "wrong username or password"
    if isinstance(e, ServiceUnavailable):
        return "server not reachable (is Neo4j running, and is the URI right?)"
    return getattr(e, "message", None) or str(e) or type(e).__name__


# ----------------------------------------------------------------------
# Connection settings (Settings > Database)
# ----------------------------------------------------------------------

class ConnectionRequest(BaseModel):
    uri: str
    user: str
    password: Optional[str] = None  # empty/None = keep the current password


def _local_only(request: Request) -> None:
    """Changing the connection or writing to a case is allowed only from this
    machine, even with --host 0.0.0.0."""
    host = request.client.host if request.client else ""
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(status_code=403, detail="Only allowed from this machine (localhost).")


_URI_SCHEMES = {"bolt", "bolt+s", "bolt+ssc", "neo4j", "neo4j+s", "neo4j+ssc"}


def _candidate(req: ConnectionRequest) -> Dict[str, str]:
    uri, user = req.uri.strip(), req.user.strip()
    if not uri or not user:
        raise HTTPException(status_code=400, detail="URI and username are required.")
    scheme = uri.split("://", 1)[0] if "://" in uri else ""
    if scheme not in _URI_SCHEMES:
        raise HTTPException(status_code=400, detail="URI must look like bolt://host:7687 or neo4j://host:7687 "
                                                    "(schemes: " + ", ".join(sorted(_URI_SCHEMES)) + ").")
    return {"uri": uri, "user": user, "password": req.password or _conn["password"]}


def _try_connection(conn: Dict[str, str]):
    """Open a driver for conn and list the project databases; returns (driver, databases)."""
    try:
        # Short timeouts so a wrong host/port fails in seconds, not after the default ~30 s
        drv = GraphDatabase.driver(conn["uri"], auth=(conn["user"], conn["password"]),
                                   connection_timeout=5.0, connection_acquisition_timeout=5.0)
    except (DriverError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid URI: {_error_text(e)}")
    try:
        drv.verify_connectivity()
        return drv, _list_databases(drv)
    except (DriverError, Neo4jError) as e:
        drv.close()
        raise HTTPException(status_code=400, detail=f"Cannot connect to {conn['uri']}: {_error_text(e)}")


@app.get("/api/connection")
def get_connection() -> Dict[str, Any]:
    """Current connection, without the password."""
    return {"uri": _conn["uri"], "user": _conn["user"], "has_password": bool(_conn["password"]),
            "database_prefix": config.DATABASE_PREFIX}


@app.post("/api/connection/test")
def test_connection(req: ConnectionRequest, request: Request) -> Dict[str, Any]:
    """Try the given settings without applying them."""
    _local_only(request)
    drv, dbs = _try_connection(_candidate(req))
    drv.close()
    return {"ok": True, "databases": dbs}


@app.post("/api/connection")
def set_connection(req: ConnectionRequest, request: Request) -> Dict[str, Any]:
    """Apply new settings after a successful test; the old driver is closed."""
    global _driver
    _local_only(request)
    conn = _candidate(req)
    drv, dbs = _try_connection(conn)
    old, _driver = _driver, drv
    _conn.update(conn)
    if old is not None:
        old.close()
    return {"ok": True, "databases": dbs}


@app.get("/api/stats")
def stats(db: str = Query(...)) -> Dict[str, Any]:
    with _session(db) as s:
        labels = {r["l"]: r["c"] for r in s.run(
            "MATCH (n) WHERE NOT n:Case UNWIND labels(n) AS l RETURN l, count(*) AS c ORDER BY c DESC")}
        types = {r["t"]: r["c"] for r in s.run(
            "MATCH ()-[r]->() RETURN type(r) AS t, count(*) AS c ORDER BY c DESC")}
    return {"labels": labels, "relationships": types}


@app.get("/api/graph")
def graph(db: str = Query(...)) -> Dict[str, Any]:
    """Every node and relationship of the database (no display limit)."""
    with _session(db) as s:
        nodes = [{"id": r["id"], "labels": sorted(r["labels"]),
                  "props": {k: _value(v) for k, v in r["props"].items()}}
                 for r in s.run("MATCH (n) WHERE NOT n:Case RETURN elementId(n) AS id, labels(n) AS labels, "
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


# ----------------------------------------------------------------------
# Case pipeline: upload -> graph (log2graph) -> anomaly detection ->
# event reconstruction -> export. Long steps run as background jobs.
# ----------------------------------------------------------------------

def _case_call(fn, *args):
    try:
        return fn(*args)
    except CaseError as e:
        raise HTTPException(status_code=e.status, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except (DriverError, Neo4jError) as e:
        raise HTTPException(status_code=503, detail=f"Neo4j: {_error_text(e)}")


@app.get("/api/case")
def case_info(db: str = Query(...)) -> Dict[str, Any]:
    """Case metadata (:Case node: source file, stage, rule source, ...) and its running job."""
    return _case_call(cases.case_info, db)


@app.post("/api/cases")
async def create_case(request: Request, name: str = Query(...), decode: bool = Query(True)) -> Dict[str, Any]:
    """New case from a Plaso CSV sent as the raw request body: the file is saved as
    dataset/uploads/<name>.csv, database sigmadft-<name> is created and the import
    job (log2graph) starts. Returns {db, job}."""
    _local_only(request)
    try:
        job = await cases.upload(name, decode, request.stream())
    except CaseError as e:
        raise HTTPException(status_code=e.status, detail=str(e))
    except (DriverError, Neo4jError) as e:
        raise HTTPException(status_code=503, detail=f"Neo4j: {_error_text(e)}")
    return {"db": job.db, "job": job.to_dict()}


class DetectRequest(BaseModel):
    rule_source: str = "all"


@app.post("/api/cases/{db}/detect")
def detect(db: str, req: DetectRequest, request: Request) -> Dict[str, Any]:
    """Anomaly detection with SigmaDFT (replaces an earlier detection and its HLEs)."""
    _local_only(request)
    return {"job": _case_call(cases.start_detect, db, req.rule_source).to_dict()}


@app.post("/api/cases/{db}/reconstruct")
def reconstruct(db: str, request: Request) -> Dict[str, Any]:
    """Event reconstruction: high-level events from the current detection."""
    _local_only(request)
    return {"job": _case_call(cases.start_reconstruct, db).to_dict()}


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str) -> Dict[str, Any]:
    return _case_call(get_job, job_id).to_dict()


@app.get("/api/export")
def export(db: str = Query(...), format: str = Query("json")) -> Response:
    """Download the case in the SigmaDFT CLI output format of its current stage."""
    filename, text = _case_call(cases.export, db, format)
    media = "application/json" if format == "json" else "text/csv"
    return Response(content=text, media_type=f"{media}; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})
