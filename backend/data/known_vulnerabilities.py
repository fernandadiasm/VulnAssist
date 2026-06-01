KNOWN_VULNERABILITIES = {
    "http trace allowed": {
        "titulo": "HTTP TRACE Allowed",
        "tipo": "Configuração insegura",
        "descricao_tecnica": "O método HTTP TRACE está habilitado no servidor web. Esse método foi criado para fins de diagnóstico, permitindo que uma requisição enviada ao servidor seja refletida na resposta.",
        "impacto": "Caso explorado em determinados cenários, o método TRACE pode auxiliar ataques de Cross-Site Tracing (XST), expondo informações sensíveis presentes em cabeçalhos HTTP, como cookies ou tokens de sessão. Embora a exploração dependa de condições específicas, a exposição desse método aumenta desnecessariamente a superfície de ataque da aplicação.",
        "recomendacoes": [
            "Desabilitar o método HTTP TRACE no servidor web.",
            "Permitir apenas métodos HTTP necessários para o funcionamento da aplicação, como GET, POST, PUT ou DELETE, conforme o caso.",
            "Validar a configuração após a alteração utilizando ferramentas como curl, navegador ou scanner de vulnerabilidades."
        ],
        "referencias": [
            "OWASP - Testing for HTTP Methods",
            "Mozilla - HTTP request methods"
        ]
    }
}