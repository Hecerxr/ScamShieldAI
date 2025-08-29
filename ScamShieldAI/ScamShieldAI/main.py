from flask import Flask, request, jsonify, render_template, flash, redirect, url_for
import requests, re, os, platform, datetime, json, logging
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, firestore

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# === CONFIG: API Keys via Environment Variables ===
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY", "")
GOOGLE_SAFE_API_KEY = os.getenv("GOOGLE_SAFE_API_KEY", "")

# === INIT FIREBASE ===
FIREBASE_CREDS_JSON = "firebase_creds.json"
db = None
try:
    if os.path.exists(FIREBASE_CREDS_JSON):
        cred = credentials.Certificate(FIREBASE_CREDS_JSON)
        firebase_admin.initialize_app(cred)
        db = firestore.client()
        logger.info("Firebase initialized successfully")
    else:
        logger.warning("Firebase credentials file not found. Logging will be local only.")
except Exception as e:
    logger.error(f"Firebase initialization failed: {e}")
    db = None

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# === AI Analysis ===
def query_gemini(content, analysis_type="general"):
    """Query Gemini AI for cybersecurity analysis"""
    if not GEMINI_API_KEY:
        return {
            "error": True,
            "message": "⚠️ GEMINI_API_KEY not configured. Please add your API key to environment variables.",
            "risk_level": "UNKNOWN"
        }
    
    # Customize prompt based on analysis type
    if analysis_type == "url":
        prompt = f"""Analyze URL: {content}

Provide:
**Status:** SAFE/SUSPICIOUS/DANGEROUS
**Risk:** LOW/MEDIUM/HIGH  
**Analysis:** Brief security assessment
**Action:** What should user do

Be concise - max 200 words."""
    elif analysis_type == "phone":
        prompt = f"""Check phone number: {content}

Provide:
**Status:** SAFE/SUSPICIOUS/SCAM
**Risk:** LOW/MEDIUM/HIGH
**Assessment:** Brief scam analysis  
**Advice:** What user should do

Be brief - max 150 words."""
    else:
        prompt = f"""Analyze for security threats: {content}

**Status:** SAFE/SUSPICIOUS/DANGEROUS
**Risk:** LOW/MEDIUM/HIGH
**Analysis:** Brief threat assessment
**Advice:** User recommendations

Max 150 words."""
    
    try:
        # Use the more stable Gemini model
        response = requests.post(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
            headers={"Content-Type": "application/json"},
            params={"key": GEMINI_API_KEY},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.2,
                    "maxOutputTokens": 300,
                    "candidateCount": 1
                }
            },
            timeout=30
        )
        
        if response.status_code != 200:
            logger.error(f"Gemini API error {response.status_code}: {response.text}")
            return {
                "error": True,
                "message": f"⚠️ AI Analysis failed (Error {response.status_code}). Please try again.",
                "risk_level": "UNKNOWN"
            }
            
        response_data = response.json()
        logger.debug(f"Gemini API response: {response_data}")
        
        if 'candidates' in response_data and response_data['candidates']:
            candidate = response_data['candidates'][0]
            
            # Check if finish reason indicates truncation
            if candidate.get('finishReason') == 'MAX_TOKENS':
                logger.warning("Response truncated due to max tokens")
            
            # Try different response structures
            analysis_text = None
            if 'content' in candidate:
                content = candidate['content']
                if 'parts' in content and content['parts']:
                    analysis_text = content['parts'][0].get('text', '')
                elif 'text' in content:
                    analysis_text = content['text']
            
            if analysis_text and analysis_text.strip():
                # Extract risk level from analysis
                risk_level = "MEDIUM"  # default
                analysis_upper = analysis_text.upper()
                if "LOW" in analysis_upper or "SAFE" in analysis_upper:
                    risk_level = "LOW"
                elif "HIGH" in analysis_upper or "DANGER" in analysis_upper:
                    risk_level = "HIGH"
                
                return {
                    "error": False,
                    "message": analysis_text,
                    "risk_level": risk_level
                }
            else:
                logger.error(f"No valid content in response: {candidate}")
                return {
                    "error": True,
                    "message": "⚠️ AI analysis was incomplete. This might be a complex case - please try a simpler input or try again.",
                    "risk_level": "UNKNOWN"
                }
        else:
            logger.error(f"Unexpected Gemini API response: {response_data}")
            return {
                "error": True,
                "message": "⚠️ Unexpected response from AI service. Please try again.",
                "risk_level": "UNKNOWN"
            }
            
    except requests.exceptions.Timeout:
        logger.error("Gemini API request timed out")
        return {
            "error": True,
            "message": "⚠️ AI analysis timed out. Please try again.",
            "risk_level": "UNKNOWN"
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Gemini API network error: {e}")
        return {
            "error": True,
            "message": f"⚠️ Network error during AI analysis: {str(e)}",
            "risk_level": "UNKNOWN"
        }
    except Exception as e:
        logger.error(f"Gemini API unexpected error: {e}")
        return {
            "error": True,
            "message": f"⚠️ Unexpected error during AI analysis: {str(e)}",
            "risk_level": "UNKNOWN"
        }

# === WHOIS Domain Age ===
def get_domain_age(domain):
    """Get domain age using WHOIS API"""
    if not WHOIS_API_KEY:
        logger.warning("WHOIS_API_KEY not configured")
        return None
        
    try:
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
        params = {
            "apiKey": WHOIS_API_KEY,
            "domainName": domain,
            "outputFormat": "JSON"
        }
        
        response = requests.get(url, params=params, timeout=10)
        if response.status_code != 200:
            logger.error(f"WHOIS API error {response.status_code}")
            return None
            
        data = response.json()
        created = data.get("WhoisRecord", {}).get("createdDate")
        if created:
            created_date = datetime.datetime.strptime(created[:10], "%Y-%m-%d")
            age_days = (datetime.datetime.utcnow() - created_date).days
            return age_days
    except Exception as e:
        logger.error(f"WHOIS lookup error: {e}")
        return None

# === Google Safe Browsing ===
def check_google_safe(url):
    """Check URL against Google Safe Browsing API"""
    if not GOOGLE_SAFE_API_KEY:
        logger.warning("GOOGLE_SAFE_API_KEY not configured")
        return False
        
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
        params = {"key": GOOGLE_SAFE_API_KEY}
        payload = {
            "client": {"clientId": "scamshield", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(api_url, params=params, json=payload, timeout=10)
        if response.status_code != 200:
            logger.error(f"Google Safe Browsing API error {response.status_code}")
            return False
            
        result = response.json()
        return bool(result.get("matches"))
    except Exception as e:
        logger.error(f"Google Safe Browsing error: {e}")
        return False

# === Scam Log ===
scam_log = []

def log_scam(input_text, result, analysis_type="general"):
    """Log analysis results locally and to Firebase"""
    entry = {
        "input": input_text,
        "analysis": result,
        "analysis_type": analysis_type,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "risk_level": result.get("risk_level", "UNKNOWN") if isinstance(result, dict) else "UNKNOWN"
    }
    
    scam_log.append(entry)
    
    # Store in Firebase if available
    if db:
        try:
            db.collection("scam_scans").add(entry)
            logger.info("Analysis logged to Firebase")
        except Exception as e:
            logger.error(f"Firebase logging error: {e}")

# === Device Scan ===
def perform_device_scan():
    """Perform basic device security scan"""
    results = []
    os_type = platform.system()
    
    results.append(f"🖥️ **Operating System:** {os_type} {platform.release()}")
    
    if os_type == "Linux":
        results.append("✅ **OS Security:** Running on secure Linux base")
    elif os_type == "Windows":
        results.append("⚠️ **OS Security:** Windows detected - ensure updates are current")
    elif os_type == "Darwin":
        results.append("✅ **OS Security:** macOS detected - generally secure")
    else:
        results.append("⚠️ **OS Security:** Unknown OS detected")
    
    # Check for root/admin privileges
    try:
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            results.append("⚠️ **Privilege Level:** Running as root - high security risk")
        elif os.name == 'nt':
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                results.append("⚠️ **Privilege Level:** Running as administrator - elevated risk")
            else:
                results.append("✅ **Privilege Level:** Standard user privileges")
        else:
            results.append("✅ **Privilege Level:** Non-root user detected")
    except:
        results.append("ℹ️ **Privilege Level:** Unable to determine privilege level")
    
    # Basic security recommendations
    results.append("🔍 **Security Scan:** Basic system check completed")
    results.append("🔒 **Recommendations:**")
    results.append("   • Keep your operating system updated")
    results.append("   • Use antivirus software")
    results.append("   • Enable firewall protection")
    results.append("   • Use VPN for public networks")
    results.append("   • Review app permissions regularly")
    
    return "\n".join(results)

# === Input Validation ===
def validate_url(url):
    """Validate URL format"""
    if not url or not isinstance(url, str):
        return False
    
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        return False
    
    try:
        parsed = urlparse(url)
        return bool(parsed.netloc)
    except:
        return False

def validate_phone(phone):
    """Validate phone number format"""
    if not phone or not isinstance(phone, str):
        return False
    
    phone = re.sub(r'[^\d+\-\(\)\s]', '', phone.strip())
    return len(phone) >= 7  # Minimum reasonable phone number length

# === Flask Routes ===
@app.route('/')
def home():
    """Home page with navigation to different analysis types"""
    return render_template("index.html")

@app.route('/url', methods=['GET', 'POST'])
def url_analysis():
    """URL safety analysis page"""
    if request.method == 'POST':
        input_data = request.form.get('input', '').strip()
        
        if not input_data:
            flash('Please enter a URL to analyze', 'warning')
            return render_template("url_analysis.html")
        
        if not validate_url(input_data):
            flash('Please enter a valid URL starting with http:// or https://', 'danger')
            return render_template("url_analysis.html")
        
        try:
            # Parse domain for additional checks
            domain = urlparse(input_data).netloc
            
            # Get AI analysis
            ai_result = query_gemini(input_data, "url")
            
            # Get domain age
            domain_age = get_domain_age(domain)
            
            # Check Google Safe Browsing
            is_flagged = check_google_safe(input_data)
            
            # Compile results
            result = {
                "url": input_data,
                "domain": domain,
                "ai_analysis": ai_result,
                "domain_age": domain_age,
                "google_safe_flagged": is_flagged,
                "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            }
            
            # Log the analysis
            log_scam(input_data, result, "url")
            
            return render_template("url_analysis.html", result=result)
            
        except Exception as e:
            logger.error(f"URL analysis error: {e}")
            flash(f'Analysis failed: {str(e)}', 'danger')
            return render_template("url_analysis.html")
    
    return render_template("url_analysis.html")

@app.route('/phone', methods=['GET', 'POST'])
def phone_verification():
    """Phone number scam verification page"""
    if request.method == 'POST':
        input_data = request.form.get('input', '').strip()
        
        if not input_data:
            flash('Please enter a phone number to analyze', 'warning')
            return render_template("phone_verification.html")
        
        if not validate_phone(input_data):
            flash('Please enter a valid phone number', 'danger')
            return render_template("phone_verification.html")
        
        try:
            # Get AI analysis
            ai_result = query_gemini(input_data, "phone")
            
            # Compile results
            result = {
                "phone": input_data,
                "ai_analysis": ai_result,
                "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            }
            
            # Log the analysis
            log_scam(input_data, result, "phone")
            
            return render_template("phone_verification.html", result=result)
            
        except Exception as e:
            logger.error(f"Phone analysis error: {e}")
            flash(f'Analysis failed: {str(e)}', 'danger')
            return render_template("phone_verification.html")
    
    return render_template("phone_verification.html")

@app.route('/device', methods=['GET', 'POST'])
def device_scan():
    """Device security scan page"""
    if request.method == 'POST':
        try:
            scan_result = perform_device_scan()
            
            result = {
                "scan_output": scan_result,
                "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "risk_level": "LOW"  # Device scans are generally low risk
            }
            
            # Log the scan
            log_scam("Device Security Scan", {"message": scan_result, "risk_level": "LOW"}, "device")
            
            return render_template("device_scan.html", result=result)
            
        except Exception as e:
            logger.error(f"Device scan error: {e}")
            flash(f'Device scan failed: {str(e)}', 'danger')
            return render_template("device_scan.html")
    
    return render_template("device_scan.html")

@app.route('/logs')
def logs():
    """API endpoint to get analysis logs"""
    return jsonify({
        "logs": scam_log[-50:],  # Return last 50 logs
        "total_count": len(scam_log)
    })

@app.route('/api/status')
def api_status():
    """API status endpoint"""
    return jsonify({
        "status": "online",
        "services": {
            "gemini_ai": bool(GEMINI_API_KEY),
            "whois_api": bool(WHOIS_API_KEY),
            "google_safe_browsing": bool(GOOGLE_SAFE_API_KEY),
            "firebase": bool(db)
        },
        "timestamp": datetime.datetime.utcnow().isoformat()
    })

# === Error Handlers ===
@app.errorhandler(404)
def not_found(error):
    return render_template("index.html"), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    flash('Internal server error occurred', 'danger')
    return render_template("index.html"), 500

# === Run App ===
if __name__ == '__main__':
    logger.info("Starting ScamShield AI application")
    app.run(host='0.0.0.0', port=5000, debug=True)
