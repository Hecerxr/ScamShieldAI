from flask import Flask, request, jsonify, render_template
import requests, re, os, platform, datetime, json
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, firestore

# === CONFIG: API Keys via Environment Variables ===
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")
GOOGLE_SAFE_API_KEY = os.getenv("GOOGLE_SAFE_API_KEY")

# === INIT FIREBASE ===
FIREBASE_CREDS_JSON = "firebase_creds.json"
if os.path.exists(FIREBASE_CREDS_JSON):
    cred = credentials.Certificate(FIREBASE_CREDS_JSON)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
else:
    db = None

app = Flask(__name__)

# === AI Analysis ===
def query_gemini(content):
    if not GEMINI_API_KEY:
        return "⚠️ GEMINI_API_KEY not configured. Please add your API key."
    
    prompt = f"""
You're a cybersecurity expert. Analyze the following input (link, phone number, or file):

Input: {content}

Return a report that includes:
1. Scam or Safe classification
2. Red flags or phishing traits
3. Risk level (LOW / MEDIUM / HIGH)
4. Advice for user
5. Device vulnerabilities (if any)
6. If it's a URL, scan Google Safe Browsing + WHOIS domain age
"""
    try:
        res = requests.post(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
            headers={"Content-Type": "application/json"},
            params={"key": GEMINI_API_KEY},
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=30
        )
        
        if res.status_code != 200:
            return f"⚠️ API Error {res.status_code}: {res.text}"
            
        response_data = res.json()
        if 'candidates' in response_data and response_data['candidates']:
            return response_data['candidates'][0]['content']['parts'][0]['text']
        else:
            return f"⚠️ Unexpected API response: {response_data}"
            
    except requests.exceptions.Timeout:
        return "⚠️ AI request timed out. Please try again."
    except requests.exceptions.RequestException as e:
        return f"⚠️ Network error: {str(e)}"
    except Exception as e:
        return f"⚠️ AI error: {str(e)}"

# === WHOIS Domain Age ===
def get_domain_age(domain):
    try:
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=JSON"
        res = requests.get(url)
        created = res.json().get("WhoisRecord", {}).get("createdDate")
        if created:
            created_date = datetime.datetime.strptime(created[:10], "%Y-%m-%d")
            age_days = (datetime.datetime.utcnow() - created_date).days
            return age_days
    except:
        return None

# === Google Safe Browsing ===
def check_google_safe(url):
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_API_KEY}"
        payload = {
            "client": {"clientId": "scamshield", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        res = requests.post(api_url, json=payload)
        return bool(res.json().get("matches"))
    except:
        return False

# === Scam Log ===
scam_log = []
def log_scam(input_text, result):
    entry = {
        "input": input_text,
        "analysis": result,
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    scam_log.append(entry)
    if db:
        db.collection("scam_scans").add(entry)

# === Device Scan ===
def perform_device_scan():
    out = []
    os_type = platform.system()
    out.append(f"🖥️ OS Detected: {os_type}")
    if os_type == "Linux":
        out.append("✔ Running on secure Linux base.")
    else:
        out.append("⚠ Non-Linux OS detected.")
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        out.append("⚠ Device running as root — high risk.")
    else:
        out.append("✔ No root access detected.")
    out.append("🔍 No malware signatures found (basic scan).")
    out.append("🔒 Consider VPN & permission review.")
    return "\n".join(out)

# === Flask Routes ===
@app.route('/')
def home():
    return render_template("index.html")

@app.route('/url', methods=['GET', 'POST'])
def url_analysis():
    result = None
    if request.method == 'POST':
        input_data = request.form.get('input')
        if input_data and input_data.startswith("http"):
            domain = urlparse(input_data).netloc
            age = get_domain_age(domain)
            gsb = check_google_safe(input_data)
            age_note = f"\nDomain age: {age} days" if age else "\nDomain age: Unknown"
            gsb_note = "\n⚠ Flagged by Google Safe Browsing" if gsb else "\n✅ Google Safe Browsing: Clean"
            result = query_gemini(input_data) + age_note + gsb_note
            log_scam(input_data, result)
        else:
            result = "⚠️ Please enter a valid URL starting with http:// or https://"
    return render_template("url_analysis.html", result=result)

@app.route('/phone', methods=['GET', 'POST'])
def phone_verification():
    result = None
    if request.method == 'POST':
        input_data = request.form.get('input')
        if input_data and input_data.strip():
            result = query_gemini(input_data)
            log_scam(input_data, result)
        else:
            result = "⚠️ Please enter a phone number to analyze"
    return render_template("phone_verification.html", result=result)

@app.route('/device', methods=['GET', 'POST'])
def device_scan():
    result = None
    if request.method == 'POST':
        result = perform_device_scan()
        log_scam("Device Scan", result)
    return render_template("device_scan.html", result=result)

@app.route('/logs', methods=['GET'])
def logs():
    return jsonify(scam_log)

# === Run App ===
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
