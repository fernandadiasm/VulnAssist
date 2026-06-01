def gerar_justificativa(cvss, epss, kev):
    motivos = []

    if kev:
        motivos.append(
            "A vulnerabilidade está presente no catálogo Known Exploited Vulnerabilities (KEV) da CISA."
        )

    if cvss is not None:
        motivos.append(
            f"A vulnerabilidade possui CVSS {cvss}."
        )

    if epss is not None:
        motivos.append(
            f"A probabilidade de exploração segundo o EPSS é de {epss:.2%}."
        )

    return " ".join(motivos)