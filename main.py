from fastapi import FastAPI
import requests

app = FastAPI()

# チェックしたいヘッダーのルールを、データとしてまとめて定義
HEADER_CHECKS = [
    {
        "name": "Strict-Transport-Security",
        "severity": "high",
        "fail_message": "HSTSヘッダーが設定されていません。",
        # 合格かどうかを判定する関数(値を受け取ってTrue/Falseを返す)
        "is_valid": lambda value: value is not None,
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "fail_message": "nosniffが設定されていません。MIMEタイプスニッフィングのリスクがあります。",
        "is_valid": lambda value: value == "nosniff",
    },
    {
        "name": "X-Frame-Options",
        "severity": "medium",
        "fail_message": "X-Frame-Optionsが設定されていません。クリックジャッキングのリスクがあります。",
        "is_valid": lambda value: value is not None and value.upper() in ("DENY", "SAMEORIGIN"),
    },
]


@app.get("/")
def read_root():
    return {"message": "Hello, Security Scanner!"}


@app.get("/api/scan")
def scan(url: str):
    response = requests.get(url, timeout=10)
    headers = response.headers

    results = []

    for check in HEADER_CHECKS:
        value = headers.get(check["name"])

        if check["is_valid"](value):
            results.append({
                "name": check["name"],
                "status": "pass",
                "severity": check["severity"],
                "message": f"設定済み: {value}",
            })
        else:
            results.append({
                "name": check["name"],
                "status": "fail",
                "severity": check["severity"],
                "message": check["fail_message"],
            })

    return {
        "url": url,
        "results": results
    }