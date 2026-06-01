import requests


def buscar_epss(cve_id: str):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    response = requests.get(url)
    data = response.json()

    if not data.get("data"):
        return {
            "epss": None,
            "percentil": None
        }

    item = data["data"][0]

    return {
        "epss": float(item["epss"]),
        "percentil": float(item["percentile"]),
        "data": item["date"]
    }