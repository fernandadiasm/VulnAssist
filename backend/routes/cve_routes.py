from fastapi import APIRouter
from backend.services.nvd_service import buscar_cve_nvd

router = APIRouter()


@router.get("/cve/{cve_id}")
def get_cve(cve_id: str):
    return buscar_cve_nvd(cve_id)