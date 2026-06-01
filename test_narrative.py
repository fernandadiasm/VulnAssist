from backend.services.narrative_service import generate_narrative

dados = {
    "cve": "CVE-2022-42889",
    "cwe": "CWE-94",
    "description": "Apache Commons Text vulnerability"
}

resultado = generate_narrative(dados)

print(resultado)