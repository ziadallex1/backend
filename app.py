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
        return add_cors(jsonify({"خطأ": "مفيش لينك"})), 400

    # ارسال الرابط للتحليل
    scan_response = requests.post(SCAN_URL, headers=HEADERS, data={"url": url})
    if scan_response.status_code != 200:
        return add_cors(jsonify({"خطأ": "فشل في إرسال الرابط"}))
    
    scan_id = scan_response.json()["data"]["id"]

    # متابعة التحليل
    analysis_result = {}
    for _ in range(10):  
        analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=HEADERS)
        analysis_result = analysis_response.json()
        status = analysis_result["data"]["attributes"]["status"]
        if status == "completed":
            break
        time.sleep(2)  

    # استخراج الإحصائيات
    stats = analysis_result["data"]["attributes"]["stats"]
    خبيث = stats["malicious"]
    آمن = stats["harmless"]
    مشبوه = stats["suspicious"]
    name = "مرحبا مريم"
    if خبيث > 0:
        الحالة = "خبيث"
    elif مشبوه > 0:
        الحالة = "مشبوه"
    else:
        الحالة = "آمن"

    النتيجة = {
        "الرابط": url,
        "الحالة": الحالة,
        "تم اكتشافه كخبيث": خبيث,
        "تم اكتشافه كآمن": آمن,
        "تم اكتشافه كمشبوه": مشبوه
    }

    return add_cors(jsonify(النتيجة))

if __name__ == "__main__":
    app.run(debug=True)
