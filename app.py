from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
import time
import os

app = Flask(__name__)
CORS(app)  

API_KEY = os.environ.get("VT_API_KEY")
if not API_KEY:
    raise ValueError("Please set the VT_API_KEY environment variable!")

HEADERS = {"x-apikey": API_KEY}
SCAN_URL = "https://www.virustotal.com/api/v3/urls"


@app.route("/", methods=["GET", "POST"])
def api_f():
    url_f = None

   
    if request.method == "GET":
        url_f = request.args.get("url")
    elif request.method == "POST":
        data_f = request.get_json()
        if data_f:
            url_f = data_f.get("url")

    if not url_f:
        return jsonify({"ERROR": "Not Found Url...."}), 400

    # إرسال الرابط للتحليل
    scan_response = requests.post(SCAN_URL, headers=HEADERS, data={"url": url_f})
    if scan_response.status_code != 200:
        return jsonify({"ERROR": "The Link was not sent"}), 400

    scan_data = scan_response.json()
    scan_id = scan_data["data"]["id"]
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"

    # انتظار انتهاء التحليل
    while True:
        analysis_response = requests.get(analysis_url, headers=HEADERS)
        if analysis_response.status_code != 200:
            return jsonify({"ERROR": "Error fetching analysis"}), 500

        analysis_result = analysis_response.json()
        status = analysis_result["data"]["attributes"]["status"]

        if status == "completed":
            break
        time.sleep(2)  # استنى ثانيتين قبل المحاولة التالية

    stats = analysis_result["data"]["attributes"]["stats"]

    malicious = stats["malicious"]
    harmless = stats["harmless"]
    suspicious = stats["suspicious"]

    if malicious > 0:
        result_status = "The Link is Malicious"
    elif suspicious > 0:
        result_status = "The Link is Suspicious"
    else:
        result_status = "The Link is Safe"

    return jsonify({
        "Plan": "Free",
        "Status": result_status,
        "Url": url_f,
        "Detected as Safe": harmless,
        "Detected as Malicious": malicious,
        "Detected as Suspicious": suspicious
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
