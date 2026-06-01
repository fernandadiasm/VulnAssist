from fastapi import APIRouter
from backend.services.nvd_service import buscar_cve_nvd
from backend.data.known_vulnerabilities import KNOWN_VULNERABILITIES

router = APIRouter()


@router.get("/search/{query}")
def search_vulnerability(query: str):
    normalized_query = query.lower().strip()

    if normalized_query.startswith("cve-"):
        return buscar_cve_nvd(normalized_query.upper())

    if normalized_query in KNOWN_VULNERABILITIES:
        return KNOWN_VULNERABILITIES[normalized_query]

    return {
        "query": query,
        "message": "Vulnerabilidade não encontrada na base local. Tente pesquisar por uma CVE ou cadastre essa vulnerabilidade na base."
    }