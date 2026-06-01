from backend.services.nvd_service import buscar_cve_nvd
from backend.services.epss_service import buscar_epss


def enriquecer_cve(cve_id: str):
    dados_nvd = buscar_cve_nvd(cve_id)

    if dados_nvd.get("erro"):
        return dados_nvd

    dados_epss = buscar_epss(cve_id)

    return {
        "identificador": dados_nvd["cve"],
        "fontes_consultadas": ["NVD", "EPSS"],
        "dados_tecnicos": dados_nvd,
        "probabilidade_exploracao": dados_epss,
        "analise": {
            "resumo": "Análise com IA ainda não implementada.",
            "impacto": "Impacto será gerado posteriormente com base nos dados coletados.",
            "recomendacoes": [
                "Recomendação será gerada posteriormente com base nas fontes consultadas."
            ]
        }
    }