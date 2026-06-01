CWE_KNOWLEDGE_BASE = {
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "description": "Falha que permite a injeção e execução de scripts maliciosos no navegador de usuários.",
        "impacts": [
            "Roubo de sessão de usuários",
            "Execução de código JavaScript malicioso",
            "Redirecionamento para páginas fraudulentas",
            "Exposição de informações sensíveis"
        ],
        "recommendations": [
            "Validar e sanitizar entradas fornecidas por usuários",
            "Aplicar encoding adequado na saída de dados",
            "Implementar Content Security Policy (CSP)",
            "Evitar renderização direta de conteúdo não confiável"
        ]
    },

    "CWE-89": {
        "name": "SQL Injection",
        "description": "Falha que permite a manipulação de consultas SQL por meio de entradas não tratadas.",
        "impacts": [
            "Acesso não autorizado a dados",
            "Exposição de informações sensíveis",
            "Alteração ou exclusão de registros",
            "Possível comprometimento do banco de dados"
        ],
        "recommendations": [
            "Utilizar consultas parametrizadas",
            "Evitar concatenação direta de entradas em queries SQL",
            "Aplicar validação de entrada",
            "Utilizar contas de banco com privilégios mínimos"
        ]
    },

    "CWE-94": {
        "name": "Code Injection",
        "description": "Falha que permite a injeção e execução de código arbitrário pela aplicação vulnerável.",
        "impacts": [
            "Execução remota de código",
            "Comprometimento total do sistema afetado",
            "Acesso não autorizado ao ambiente",
            "Movimentação lateral na infraestrutura"
        ],
        "recommendations": [
            "Atualizar o componente vulnerável",
            "Restringir funcionalidades que executam código dinâmico",
            "Validar e sanitizar entradas de usuário",
            "Aplicar controles de privilégio mínimo"
        ]
    },

    "CWE-22": {
        "name": "Path Traversal",
        "description": "Falha que permite acessar arquivos fora do diretório esperado pela aplicação.",
        "impacts": [
            "Leitura de arquivos sensíveis",
            "Exposição de configurações internas",
            "Acesso a credenciais armazenadas",
            "Possível comprometimento do servidor"
        ],
        "recommendations": [
            "Validar caminhos informados pelo usuário",
            "Bloquear sequências como ../",
            "Utilizar listas de diretórios permitidos",
            "Evitar expor caminhos internos da aplicação"
        ]
    }
}

def get_cwe_knowledge(cwe_id: str):
    if not cwe_id:
        return None

    return CWE_KNOWLEDGE_BASE.get(cwe_id.upper())