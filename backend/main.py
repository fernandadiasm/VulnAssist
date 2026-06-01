from fastapi import FastAPI
from backend.routes.cve_routes import router as cve_router
from backend.routes.search_routes import router as search_router
from backend.routes.enrichment_routes import router as enrichment_router
from backend.routes.report_routes import router as report_router

app = FastAPI()

app.include_router(cve_router)
app.include_router(search_router)
app.include_router(enrichment_router)
app.include_router(report_router)


@app.get("/")
def home():
    return {
        "project": "VulnAssist",
        "status": "running"
    }