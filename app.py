from flask import Flask, request, Response
import requests, time, json

app = Flask(__name__)

API_KEY = "0dabff120b09c5bf795801159af98b0032aa7d44ea04664f1ea311dd64ee08dc"
HEADERS = {"x-apikey": API_KEY}
SCAN_URL = "https://www.virustotal.com/api/v3/urls"

# إضافة CORS
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response

@app.route("/", methods=["GET"])
def scan_url():
    url = request.args.get("url")
    if not url:
        result = {"خطأ": "مفيش رابط مدخل"}
        return add_cors(Response(
            json.dumps(result, ensure_ascii=False),
            content_type="application/json; charset=utf-8"
        )), 400

    # إرسال الرابط لفيروس توتال
    scan_response = requests.post(SCAN_URL, headers=HEADERS, data={"url": url})
    if scan_response.status_code != 200:
        result = {"خطأ": "فشل في إرسال الرابط"}
        return add_cors(Response(
            json.dumps(result, ensure_ascii=False),
            content_type="application/json; charset=utf-8"
        ))

    scan_id = scan_response.json()["data"]["id"]

    # متابعة النتيجة
    analysis_result = {}
    for _ in range(10):
        analysis_response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{scan_id}", 
            headers=HEADERS
        )
        analysis_result = analysis_response.json()
        status = analysis_result["data"]["attributes"]["status"]
        if status == "completed":
            break
        time.sleep(2)

    stats = analysis_result["data"]["attributes"]["stats"]

    malicious = stats["malicious"]
    harmless = stats["harmless"]
    suspicious = stats["suspicious"]

    if malicious > 0:
        status_text = "خبيث"
    elif suspicious > 0:
        status_text = "مشبوه"
    else:
        status_text = "آمن"

    result = {
        "الحالة": status_text,
        "الرابط": url,
        "تم اكتشافه كآمن": harmless,
        "تم اكتشافه كخبيث": malicious,
        "تم اكتشافه كمشبوه": suspicious
    }

    return add_cors(Response(
        json.dumps(result, ensure_ascii=False),
        content_type="application/json; charset=utf-8"
    ))

if __name__ == "__main__":
    app.run(debug=True)

