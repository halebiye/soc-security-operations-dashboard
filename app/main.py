"""FastAPI composition root and HTTP interface for a loopback-only SOC lab."""

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import __version__
from app.config import ROOT, DetectionConfig, database_path, load_config
from app.detection import catalog, config_hash
from app.ingestion import MAX_UPLOAD_BYTES, ImportErrorDetail, parse_upload
from app.models import AlertFilters, CaseUpdate, Severity, Status
from app.reporting import render_report
from app.storage import CaseConflict, Repository

STATIC = Path(__file__).parent / "static"


def alert_filters(
    severity: Severity | None = None,
    status: Status | None = None,
    source_ip: str | None = None,
    username: Annotated[str | None, Query(max_length=100)] = None,
    rule_id: Annotated[str | None, Query(pattern=r"^SOC-00[1-7]$")] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    start: str | None = None,
    end: str | None = None,
) -> AlertFilters:
    try:
        return AlertFilters(
            severity=severity,
            status=status,
            source_ip=source_ip,
            username=username,
            rule_id=rule_id,
            q=q,
            start=start,
            end=end,
        )
    except ValidationError as exc:
        raise HTTPException(
            422, detail=exc.errors(include_input=False, include_context=False, include_url=False)
        ) from exc


def create_app(db_path: Path | None = None, detection_config: DetectionConfig | None = None) -> FastAPI:
    repository = Repository(db_path or database_path())
    config = detection_config or load_config()

    @asynccontextmanager
    async def lifespan(application):
        repository.initialize()
        yield

    application = FastAPI(
        title="SOC Security Operations Dashboard",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
    )
    application.state.repository = repository
    application.state.config = config
    application.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"]
    )

    @application.middleware("http")
    async def local_boundary(request: Request, call_next):
        if request.method in {"POST", "PATCH", "PUT", "DELETE"}:
            origin = request.headers.get("origin")
            expected_origin = f"{request.url.scheme}://{request.headers.get('host', '')}"
            if origin and origin != expected_origin:
                return JSONResponse({"detail": "Cross-origin changes are blocked"}, status_code=403)
            if request.headers.get("x-soc-client") != "dashboard":
                return JSONResponse(
                    {"detail": "Mutation requests require X-SOC-Client: dashboard"}, status_code=403
                )
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @application.get("/health")
    def health():
        with repository.connection() as connection:
            connection.execute("SELECT 1 FROM schema_version").fetchone()
        return {"status": "ok", "version": __version__, "storage": "sqlite", "synthetic_only": True}

    @application.get("/api/meta")
    def meta():
        return {
            "version": __version__,
            "rules": catalog(config),
            "config": config.model_dump(),
            "config_hash": config_hash(config),
            "synthetic_only": True,
            "limits": {"upload_bytes": MAX_UPLOAD_BYTES, "events_per_import": 5000, "stored_events": 20000},
        }

    @application.get("/api/dashboard")
    def dashboard():
        return repository.summary()

    @application.get("/api/alerts")
    def alerts(
        filters: Annotated[AlertFilters, Depends(alert_filters)],
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        return repository.list_alerts(filters, limit, offset)

    @application.get("/api/alerts/{alert_id}")
    def alert_detail(alert_id: int):
        result = repository.detail(alert_id)
        if result is None:
            raise HTTPException(404, "Alert not found")
        return result

    @application.patch("/api/alerts/{alert_id}")
    def update_alert(alert_id: int, update: CaseUpdate):
        try:
            result = repository.update_case(alert_id, update)
        except CaseConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        if result is None:
            raise HTTPException(404, "Alert not found")
        return result

    @application.get("/api/events")
    def events(
        q: Annotated[str, Query(max_length=200)] = "",
        event_type: Literal["authentication_success", "authentication_failure"] | None = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        return repository.list_events(q, event_type, limit, offset)

    @application.get("/api/imports")
    def imports():
        with repository.connection() as connection:
            return {
                "items": [
                    dict(row) for row in connection.execute("SELECT * FROM imports ORDER BY id DESC LIMIT 20")
                ]
            }

    @application.post("/api/ingest", status_code=201)
    async def ingest(file: Annotated[UploadFile, File()]):
        try:
            content = await file.read(MAX_UPLOAD_BYTES + 1)
            parsed = parse_upload(content, file.filename or "upload")
            # Parse off the write path; synchronous CPU/database work runs in the worker pool.
            from starlette.concurrency import run_in_threadpool

            return await run_in_threadpool(repository.ingest, parsed, file.filename or "upload", config)
        except ImportErrorDetail as exc:
            raise HTTPException(422, str(exc)) from exc
        finally:
            await file.close()

    @application.post("/api/demo", status_code=201)
    def demo():
        sample = ROOT / "sample_data/security_events.json"
        parsed = parse_upload(sample.read_bytes(), sample.name)
        return repository.ingest(parsed, "Built-in synthetic scenarios", config)

    @application.post("/api/detections/run")
    def detections():
        return repository.run_detections(config)

    @application.get("/api/reports/{output_format}")
    def report(
        output_format: Literal["json", "html", "markdown"],
        filters: Annotated[AlertFilters, Depends(alert_filters)],
    ):
        data = repository.report_data(filters, config)
        content, media_type = render_report(data, output_format)
        extension = "md" if output_format == "markdown" else output_format
        return Response(
            content,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="soc-investigation-report.{extension}"'},
        )

    @application.get("/api/samples/{extension}")
    def download_sample(extension: Literal["csv", "json"]):
        return FileResponse(
            ROOT / f"sample_data/security_events.{extension}", filename=f"security_events.{extension}"
        )

    application.mount("/static", StaticFiles(directory=STATIC), name="static")

    @application.get("/")
    @application.get("/alerts/{alert_id}")
    def index(alert_id: int | None = None):
        return FileResponse(STATIC / "index.html")

    return application


app = create_app()
