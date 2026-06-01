from backend.knowledge.cwe_mapping import get_cwe_knowledge


def generate_narrative(vulnerability_data: dict):
    cwe = vulnerability_data.get("cwe")
    cwe_info = get_cwe_knowledge(cwe)

    if not cwe_info:
        return {
            "tipo_vulnerabilidade": "Tipo de vulnerabilidade não mapeado",
            "descricao_tecnica": vulnerability_data.get("description"),
            "impacto": [
                "O impacto deve ser avaliado com base no contexto do ativo afetado, exposição do serviço e criticidade do ambiente."
            ],
            "recomendacoes": [
                "Analisar a documentação oficial do fornecedor.",
                "Aplicar atualizações de segurança disponíveis.",
                "Revisar configurações do serviço afetado.",
                "Monitorar evidências de exploração."
            ]
        }

    return {
        "tipo_vulnerabilidade": cwe_info["name"],
        "descricao_tecnica": cwe_info["description"],
        "impacto": cwe_info["impacts"],
        "recomendacoes": cwe_info["recommendations"]
    }