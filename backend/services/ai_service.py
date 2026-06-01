import json
import os

from dotenv import load_dotenv
from google import genai

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))


def gerar_textos_com_ia(dados: dict):
    prompt = f"""
Você é um especialista em Gestão de Vulnerabilidades e Blue Team.

Sua tarefa é gerar textos técnicos em português do Brasil para um relatório de vulnerabilidade.

REGRAS IMPORTANTES:
- Não invente dados.
- Use apenas as informações fornecidas.
- Não crie CVEs, versões, exploits ou referências que não estejam nos dados.
- Escreva de forma profissional, clara e objetiva.
- A descrição e o impacto devem ser em texto corrido.
- As recomendações devem ser uma lista.
- Retorne apenas JSON válido.

DADOS DA VULNERABILIDADE:
{json.dumps(dados, ensure_ascii=False, indent=2)}

FORMATO DE RESPOSTA:
{{
  "resumo_executivo": "...",
  "descricao": "...",
  "impacto": "...",
  "recomendacoes": [
    "...",
    "...",
    "..."
  ]
}}
"""

    response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents=prompt,
    )

    texto = response.text.strip()

    if texto.startswith("```json"):
        texto = texto.replace("```json", "").replace("```", "").strip()
    elif texto.startswith("```"):
        texto = texto.replace("```", "").strip()

    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        return {
            "erro": "A IA retornou uma resposta que não estava em JSON válido.",
            "resposta_bruta": texto
        }