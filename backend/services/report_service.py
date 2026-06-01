from backend.services.enrichment_service import enriquecer_cve


def gerar_relatorio_cve(cve_id: str):
    dados = enriquecer_cve(cve_id)

    if dados.get("erro"):
        return dados

    tecnico = dados["dados_tecnicos"]
    analise = dados["analise"]

    descricao = (
        f"A vulnerabilidade {tecnico['cve']} está relacionada a uma falha de segurança "
        f"identificada no componente analisado. De acordo com as informações obtidas nas "
        f"fontes consultadas, a falha possui severidade {dados['severidade']}, CVSS "
        f"{tecnico.get('cvss')} e está associada à fraqueza {', '.join(tecnico.get('cwes', []))}.\n\n"
        f"{tecnico['descricao']}"
    )

    impacto = (
        f"A exploração bem-sucedida dessa vulnerabilidade pode comprometer a segurança "
        f"do ambiente afetado, considerando os impactos descritos no vetor CVSS "
        f"{tecnico.get('vetor_cvss')}. A prioridade de tratamento foi classificada como "
        f"{dados['prioridade']} pelo VulnAssist. {analise['justificativa']}"
    )

    return {
        "titulo": f"{tecnico['cve']} - Vulnerabilidade em componente de software",
        "severidade": dados["severidade"],
        "prioridade": dados["prioridade"],
        "descricao": descricao,
        "impacto": impacto,
        "recomendacoes": analise["recomendacoes"],
        "referencias": tecnico.get("referencias", [])
    }