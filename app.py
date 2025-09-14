from flask import Flask , jsonify , request
import requests 

app = Flask(__name__)

API_KEY = "0dabff120b09c5bf795801159af98b0032aa7d44ea04664f1ea311dd64ee08dc"
HEADERS = {"x-apikey": API_KEY}
SCAN_URL= "https://www.virustotal.com/api/v3/urls"


@app.route("/" , methods=["GET" , "POST"])
def api_f():
    url_f = None
    
    if request.method == "GET":
        url_f = request.args.get("url")
    if request.method == "POST": 
        data_f = request.get_json()
        if data_f:
            url_f = data_f.get("url")
    
    if not url_f:
        return jsonify({"ERROR" : "Not Found Url...."}),400
    
    scan_response = requests.post(SCAN_URL , headers=HEADERS , data={"url" : url_f})
    if scan_response.status_code != 200:
        return jsonify({"ERROR" : "The Link was not sent"})
      
    scan_data = scan_response.json()
    scan_id = scan_data["data"]["id"]
    
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    analysis_response = requests.get(analysis_url , headers=HEADERS)
    
    analysis_result = analysis_response.json()
    stats = analysis_result["data"]["attributes"]["stats"] 
    
    malicious = stats ["malicious"]
    harmless = stats  ["harmless"]
    suspicious = stats ["suspicious"]
    
    free = "Free"
    
    if malicious > 0 : 
        status = "The  Link is Malicious"            
    elif suspicious > 0 : 
        status = "The Link is Suspicious"
    else :
        status = "The Link is Safe"
    
    return jsonify({
        "This is the plan." :free ,
        "Status " : status , 
        "Url" : url_f , 
        "Number of times detected as Safe " : harmless,
        "Number of times detected  as malicious" : malicious,
        "Number of times detected as suspicious" : suspicious
    })


if __name__ == "__main__":
    app.run(debug=True , port=5000)
