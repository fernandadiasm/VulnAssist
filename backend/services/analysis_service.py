def gerar_justificativa(cvss, epss, kev):
    motivos = []

    if kev:
        motivos.append(
            "A vulnerabilidade está presente no catálogo Known Exploited Vulnerabilities (KEV) da CISA."
        )

    if cvss is not None:
        motivos.append(f"A vulnerabilidade possui CVSS {cvss}.")

    if epss is not None:
        motivos.append(
            f"A probabilidade de exploração segundo o EPSS é de {epss:.2%}."
        )

    return " ".join(motivos)


def gerar_resumo_tecnico(cve_id, severidade, prioridade, cwes):
    cwes_texto = ", ".join(cwes) if cwes else "não informado"

    return (
        f"A vulnerabilidade {cve_id} possui severidade {severidade} "
        f"e foi classificada pelo VulnAssist com prioridade {prioridade}. "
        f"A fraqueza associada é {cwes_texto}."
    )


def gerar_recomendacoes_iniciais(kev):
    recomendacoes = [
        "Aplicar as correções ou atualizações disponibilizadas pelo fornecedor.",
        "Validar se os ativos afetados utilizam versões vulneráveis do componente.",
        "Priorizar a correção em ativos expostos à internet ou críticos para o negócio."
    ]

    if kev:
        recomendacoes.insert(
            0,
            "Tratar a vulnerabilidade com urgência, pois há indicação de exploração conhecida."
        )

    return recomendacoes