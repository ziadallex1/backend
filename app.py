from flask import Flask, request, Response
import requests, time, json

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
        return add_cors(Response(
            json.dumps({"خطأ": "من فضلك أدخل رابط"}, ensure_ascii=False, indent=4),
            content_type="application/json; charset=utf-8"
        )), 400

    
    scan_response = requests.post(SCAN_URL, headers=HEADERS, data={"url": url})
    if scan_response.status_code != 200:
        return add_cors(Response(
            json.dumps({"خطأ": "فشل إرسال الرابط"}, ensure_ascii=False, indent=4),
            content_type="application/json; charset=utf-8"
        ))

    scan_id = scan_response.json()["data"]["id"]

    
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

    stats = analysis_result["data"]["attributes"].get(
        "stats", {"malicious": 0, "harmless": 0, "suspicious": 0}
    )
    malicious = stats["malicious"]
    harmless = stats["harmless"]
    suspicious = stats["suspicious"]

    if malicious > 0:
        status_text = "خبيث"
        
    elif suspicious > 0:
        status_text = "مشبوه"
    else:
        status_text = "آمن"
 
    r = None    
    if status_text == "خبيث":   
        r =  "الرابط ده بيحاول ينزل ملف ضار على جهازك. متحمّلوش نهائيًا عشان ماتتعرضش للاختراق أو الفيروسات."
    elif status_text == "مشبوه" : 
        r = "الرابط ده مشبوه وممكن يكون في محاولة نصب أو اختراق. متفتحوش غير لو متأكد من المصدر."
    elif status_text == "آمن":
        r = "الرابط ده آمن ومفيهوش خطر ظاهر، بس خليك دايمًا حريص وماتدخلش بياناتك الشخصية إلا في مواقع موثوق فيها."
        
    result = {
        "الحالة": status_text,
        "الرابط": url,
        "تم اكتشافه كآمن": harmless,
        "تم اكتشافه كخبيث": malicious,
        "تم اكتشافه كمشبوه": suspicious,
        "التوعية" : r
    }

    return add_cors(Response(
        json.dumps(result, ensure_ascii=False, indent=4, sort_keys=False),
        content_type="application/json; charset=utf-8"
    ))

if __name__ == "__main__":
    app.run(debug=True)



