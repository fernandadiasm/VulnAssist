from backend.services.enrichment_service import enriquecer_cve
from backend.services.narrative_service import generate_narrative


def gerar_relatorio_cve(cve_id: str):
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

    descricao = (
        f"A vulnerabilidade {tecnico['cve']} está associada à categoria "
        f"{narrativa['tipo_vulnerabilidade']}."
        f"\n\n{narrativa['descricao_tecnica']}"
        f"\n\nDe acordo com as fontes consultadas, a falha possui severidade "
        f"{dados['severidade']}, CVSS {tecnico.get('cvss')} "
        f"e está associada à fraqueza {', '.join(cwes) if cwes else 'não informada'}."
    )

    impacto = (
        "A exploração bem-sucedida dessa vulnerabilidade pode resultar em: "
        + "; ".join(narrativa["impacto"])
        + ". "
        f"A prioridade de tratamento foi classificada como {dados['prioridade']} "
        f"pelo VulnAssist. {analise['justificativa']}"
    )
    
    resumo_executivo = (
    f"A vulnerabilidade {tecnico['cve']} foi classificada com severidade "
    f"{dados['severidade']} e prioridade {dados['prioridade']} pelo VulnAssist. "
    f"A falha está relacionada a {narrativa['tipo_vulnerabilidade']} "
    f"e deve ser tratada com atenção, especialmente caso o componente afetado "
    f"esteja presente em ativos expostos à internet ou críticos para o negócio."
    )

    recomendacoes = list(dict.fromkeys(
        narrativa["recomendacoes"] + analise["recomendacoes"]
    ))

    return {
        "titulo": f"{tecnico['cve']} - {narrativa['tipo_vulnerabilidade']}",
        "severidade": dados["severidade"],
        "prioridade": dados["prioridade"],
        "resumo_executivo": resumo_executivo,            
        "descricao": descricao,
        "impacto": impacto,
        "recomendacoes": recomendacoes,
        "referencias": tecnico.get("referencias", []),
        "dados_tecnicos": {
        "cvss": tecnico.get("cvss"),
        "vetor_cvss": tecnico.get("vetor_cvss"),
        "cwes": cwes,
        "epss": dados.get("probabilidade_exploracao", {}).get("epss"),
        "epss_percentil": dados.get("probabilidade_exploracao", {}).get("percentil"),
        "epss_data": dados.get("probabilidade_exploracao", {}).get("data"),
        "cisa_kev": dados.get("exploracao_conhecida", {}).get("esta_no_kev")
    }
    }