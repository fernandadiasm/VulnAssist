from fastapi import APIRouter
from backend.services.report_service import gerar_relatorio_cve

router = APIRouter()


@router.get("/report/{cve_id}")
def report_cve(cve_id: str):
    return gerar_relatorio_cve(cve_id.upper())