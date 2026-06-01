def calcular_prioridade(cvss, epss, kev):
    if kev:
        return "CRÍTICA"

    if cvss is None:
        return "DESCONHECIDA"

    if cvss >= 9 and epss is not None and epss >= 0.7:
        return "CRÍTICA"

    if cvss >= 8:
        return "ALTA"

    if epss is not None and epss >= 0.5:
        return "ALTA"

    if cvss >= 5:
        return "MÉDIA"

    return "BAIXA"