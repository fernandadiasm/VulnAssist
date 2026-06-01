from backend.services.nvd_service import buscar_cve_nvd
from backend.services.epss_service import buscar_epss
from backend.services.cisa_service import buscar_cisa_kev
from backend.services.prioritization_service import calcular_prioridade
from backend.services.analysis_service import (
    gerar_justificativa,
    gerar_resumo_tecnico,
    gerar_recomendacoes_iniciais
)

def enriquecer_cve(cve_id: str):
    dados_nvd = buscar_cve_nvd(cve_id)

    if dados_nvd.get("erro"):
        return dados_nvd

    dados_epss = buscar_epss(cve_id)
    dados_cisa = buscar_cisa_kev(cve_id)

    prioridade = calcular_prioridade(
        dados_nvd.get("cvss"),
        dados_epss.get("epss"),
        dados_cisa.get("esta_no_kev")
    )

    justificativa = gerar_justificativa(
    dados_nvd.get("cvss"),
    dados_epss.get("epss"),
    dados_cisa.get("esta_no_kev")
    )
    
    resumo = gerar_resumo_tecnico(
    dados_nvd.get("cve"),
    dados_nvd.get("severidade"),
    prioridade,
    dados_nvd.get("cwes")
    )

    recomendacoes = gerar_recomendacoes_iniciais(
    dados_cisa.get("esta_no_kev")
    )
    
    return {
        "identificador": dados_nvd["cve"],
        "severidade": dados_nvd["severidade"],
        "prioridade": prioridade,
        "fontes_consultadas": ["NVD", "EPSS", "CISA KEV"],
        "dados_tecnicos": dados_nvd,
        "probabilidade_exploracao": dados_epss,
        "exploracao_conhecida": dados_cisa,
        "analise": {
            "justificativa": justificativa,
            "resumo": resumo,
            "impacto": "Impacto será gerado posteriormente com IA com base nos dados coletados.",
            "recomendacoes": recomendacoes
}
    }