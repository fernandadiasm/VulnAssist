from fastapi import FastAPI
import requests

app = FastAPI()


@app.get("/")
def home():
    return {
        "project": "VulnAssist",
        "status": "running"
    }


@app.get("/cve/{cve_id}")
def get_cve(cve_id: str):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    response = requests.get(url)
    data = response.json()

    if not data.get("vulnerabilities"):
        return {"erro": "CVE não encontrada"}

    vuln = data["vulnerabilities"][0]["cve"]

    descricao = vuln["descriptions"][0]["value"]

    metricas = vuln.get("metrics", {})

    cvss_score = None
    severidade = None
    vetor = None

    if "cvssMetricV31" in metricas:
        cvss = metricas["cvssMetricV31"][0]

        cvss_score = cvss["cvssData"]["baseScore"]
        severidade = cvss["cvssData"]["baseSeverity"]
        vetor = cvss["cvssData"]["vectorString"]

    resultado = {
        "cve": vuln["id"],
        "publicada_em": vuln["published"],
        "ultima_atualizacao": vuln["lastModified"],
        "cvss": cvss_score,
        "severidade": severidade,
        "vetor_cvss": vetor,
        "descricao": descricao
    }

    return resultado