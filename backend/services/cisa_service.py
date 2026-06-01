import requests


def buscar_cisa_kev(cve_id: str):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    response = requests.get(url)
    data = response.json()

    for item in data.get("vulnerabilities", []):
        if item.get("cveID") == cve_id:
            return {
                "esta_no_kev": True,
                "fornecedor": item.get("vendorProject"),
                "produto": item.get("product"),
                "nome_vulnerabilidade": item.get("vulnerabilityName"),
                "data_adicionada": item.get("dateAdded"),
                "descricao_curta": item.get("shortDescription"),
                "acao_requerida": item.get("requiredAction"),
                "uso_em_ransomware": item.get("knownRansomwareCampaignUse"),
                "data_limite": item.get("dueDate"),
                "cwes": item.get("cwes", []),
                "observacoes": item.get("notes")
            }

    return {
        "esta_no_kev": False
    }