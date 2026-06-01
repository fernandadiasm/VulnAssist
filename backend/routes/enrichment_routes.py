from fastapi import APIRouter
from backend.services.enrichment_service import enriquecer_cve

router = APIRouter()


@router.get("/enrich/{cve_id}")
def enrich_cve(cve_id: str):
    return enriquecer_cve(cve_id.upper())