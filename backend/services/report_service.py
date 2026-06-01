from backend.services.enrichment_service import enriquecer_cve


def gerar_relatorio_cve(cve_id: str):
    dados = enriquecer_cve(cve_id)

    if dados.get("erro"):
        return dados

    tecnico = dados["dados_tecnicos"]
    analise = dados["analise"]

    return {
        "titulo": f"{tecnico['cve']} - Vulnerabilidade em componente de software",
        "severidade": dados["severidade"],
        "prioridade": dados["prioridade"],
        "descricao": (
            f"{tecnico['descricao']}\n\n"
            f"{analise['resumo']}"
        ),
        "impacto": analise["impacto"],
        "justificativa_prioridade": analise["justificativa"],
        "recomendacoes": analise["recomendacoes"],
        "referencias": tecnico.get("referencias", [])
    }