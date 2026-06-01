from backend.services.ai_service import gerar_textos_com_ia

dados = {
    "cve": "CVE-2022-42889",
    "tipo_vulnerabilidade": "Code Injection",
    "cvss": 9.8,
    "severidade": "CRITICAL",
    "prioridade": "CRÍTICA",
    "cwe": "CWE-94",
    "epss": 0.94251,
    "esta_no_kev": False,
    "descricao_original": "Apache Commons Text performs variable interpolation..."
}

resultado = gerar_textos_com_ia(dados)

print(resultado)