from fastapi import APIRouter

from backend.services.enrichment_service import enriquecer_cve
from backend.services.narrative_service import generate_narrative
from backend.services.ai_service import gerar_textos_com_ia

router = APIRouter()


@router.get("/report-ai/{cve_id}")
def gerar_relatorio_com_ia(cve_id: str):
    dados = enriquecer_cve(cve_id)

    if dados.get("erro"):
        return dados

    tecnico = dados["dados_tecnicos"]
    analise = dados["analise"]

    cwes = tecnico.get("cwes", [])
    cwe_principal = cwes[0] if cwes else None

    narrativa = generate_narrative({
        "cve": tecnico["cve"],
        "cwe": cwe_principal,
        "description": tecnico.get("descricao")
    })

    dados_para_ia = {
        "cve": tecnico.get("cve"),
        "severidade": dados.get("severidade"),
        "prioridade": dados.get("prioridade"),
        "cvss": tecnico.get("cvss"),
        "vetor_cvss": tecnico.get("vetor_cvss"),
        "cwes": cwes,
        "tipo_vulnerabilidade": narrativa.get("tipo_vulnerabilidade"),
        "descricao_tecnica_base": narrativa.get("descricao_tecnica"),
        "impactos_base": narrativa.get("impacto"),
        "recomendacoes_base": narrativa.get("recomendacoes"),
        "epss": dados.get("probabilidade_exploracao", {}).get("epss"),
        "epss_percentil": dados.get("probabilidade_exploracao", {}).get("percentil"),
        "epss_data": dados.get("probabilidade_exploracao", {}).get("data"),
        "cisa_kev": dados.get("exploracao_conhecida", {}).get("esta_no_kev"),
        "descricao_original": tecnico.get("descricao"),
        "referencias": tecnico.get("referencias", [])
    }

    textos_ia = gerar_textos_com_ia(dados_para_ia)

    if textos_ia.get("erro"):
        return {
            "erro": "Falha ao gerar textos com IA",
            "detalhes": textos_ia,
            "dados_base": dados_para_ia
        }

    return {
        "titulo": f"{tecnico['cve']} - {narrativa['tipo_vulnerabilidade']}",
        "severidade": dados["severidade"],
        "prioridade": dados["prioridade"],
        "resumo_executivo": textos_ia.get("resumo_executivo"),
        "descricao": textos_ia.get("descricao"),
        "impacto": textos_ia.get("impacto"),
        "recomendacoes": textos_ia.get("recomendacoes"),
        "referencias": tecnico.get("referencias", []),
        "dados_tecnicos": {
            "cvss": tecnico.get("cvss"),
            "vetor_cvss": tecnico.get("vetor_cvss"),
            "cwes": cwes,
            "epss": dados.get("probabilidade_exploracao", {}).get("epss"),
            "epss_percentil": dados.get("probabilidade_exploracao", {}).get("percentil"),
            "epss_data": dados.get("probabilidade_exploracao", {}).get("data"),
            "cisa_kev": dados.get("exploracao_conhecida", {}).get("esta_no_kev")
        },
        "gerado_com_ia": True
    }