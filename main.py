from fastapi import FastAPI
import requests

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello, Security Scanner!"}


@app.get("/api/scan")
def scan(url: str):
    response = requests.get(url, timeout=10)
    headers = response.headers

    results = []

    # HSTSチェック
    hsts = headers.get("Strict-Transport-Security")
    if hsts is None:
        results.append({
            "name": "Strict-Transport-Security",
            "status": "fail",
            "severity": "high",
            "message": "HSTSヘッダーが設定されていません。"
        })
    else:
        results.append({
            "name": "Strict-Transport-Security",
            "status": "pass",
            "severity": "high",
            "message": f"設定済み: {hsts}"
        })

    # X-Content-Type-Options チェック
    xcto = headers.get("X-Content-Type-Options")
    if xcto != "nosniff":
        results.append({
            "name": "X-Content-Type-Options",
            "status": "fail",
            "severity": "medium",
            "message": "nosniffが設定されていません。MIMEタイプスニッフィングのリスクがあります。"
    })
    else:
        results.append({
            "name": "X-Content-Type-Options",
            "status": "pass",
            "severity": "medium",
            "message": "設定済み"
        })

    return {
        "url": url,
        "results": results
    }