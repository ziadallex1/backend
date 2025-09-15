from flask import Flask, jsonify, request
import requests, time

app = Flask(__name__)

API_KEY = "0dabff120b09c5bf795801159af98b0032aa7d44ea04664f1ea311dd64ee08dc"
HEADERS = {"x-apikey": API_KEY}
SCAN_URL = "https://www.virustotal.com/api/v3/urls"

def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response

@app.route("/", methods=["GET"])
def scan_url():
    url = request.args.get("url")
    if not url:
        return add_cors(jsonify({"error": "No URL provided"})), 400

    # 1. إرسال اللينك
    scan_response = requests.post(SCAN_URL, headers=HEADERS, data={"url": url})
    if scan_response.status_code != 200:
        return add_cors(jsonify({"error": "Failed to submit URL"}))
    
    scan_id = scan_response.json()["data"]["id"]

    # 2. عمل polling للنتيجة (للديمو)
    analysis_result = {}
    for _ in range(10):  # نجرب 10 مرات مع تأخير
        analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=HEADERS)
        analysis_result = analysis_response.json()
        status = analysis_result["data"]["attributes"]["status"]
        if status == "completed":
            break
        time.sleep(2)  # انتظر ثانيتين قبل المحاولة التالية

    stats = analysis_result["data"]["attributes"].get("stats", {"malicious":0,"harmless":0,"suspicious":0})
    malicious = stats["malicious"]
    harmless = stats["harmless"]
    suspicious = stats["suspicious"]

    if malicious > 0:
        status_text = "Malicious"
    elif suspicious > 0:
        status_text = "Suspicious"
    else:
        status_text = "Safe"

    result = {
        "Url": url,
        "Status": status_text,
        "Detected as Malicious": malicious,
        "Detected as Safe": harmless,
        "Detected as Suspicious": suspicious
    }

    return add_cors(jsonify(result))

if __name__ == "__main__":
    app.run(debug=True)

