import re
import socket
import ssl
import whois
import datetime
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import joblib
import numpy as np
import os

# Load ML Model if exists
try:
    ML_MODEL = joblib.load(os.path.join(os.path.dirname(__file__), 'phishing_rf_model.pkl'))
except:
    ML_MODEL = None

def analyze_url(url):
    """
    Comprehensive analysis combining Heuristics, Domain lookup (Creation/Expiry),
    SSL (Issuer/Expiry), Free Threat API (URLHaus), Content Inspection, and ML.
    """
    report = {
        "url": url,
        "score": 0,
        "status": "Safe",
        "url_features": [],
        "domain_info": [],
        "ssl_check": [],
        "content_analysis": [],
        "api_reports": [],
        "ml_prediction": {}
    }
    
    # Base url prep
    original_url = url
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        domain_no_port = domain.split(':')[0]
        path = parsed_url.path
    except Exception:
        report["status"] = "Invalid"
        return report

    ml_url_length = len(original_url)
    ml_domain_age = 0  # Default to highly suspicious (0 days old) if whois fails
    ml_num_subdomains = 0
    ml_has_https = 1 if original_url.startswith('https') else 0
    ml_is_blacklisted = 0
    
    risk_points = 0 
    
    # ---------------------------------------------
    # 1. URL FEATURE ANALYZER
    # ---------------------------------------------
    is_ip = False
    if re.match(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", domain_no_port):
        report["url_features"].append({"type": "danger", "message": "Domain is an IP Address. Professional sites rarely use bare IPs."})
        risk_points += 25
        is_ip = True
    else:
        report["url_features"].append({"type": "success", "message": "Standard domain name format used."})
        
        # Check suspicious TLDs
        if '.' in domain_no_port:
            tld = domain_no_port.split('.')[-1].lower()
            common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'in', 'co', 'uk', 'us', 'ca', 'au', 'de', 'fr', 'io', 'app', 'dev', 'info']
            if tld not in common_tlds and not re.match(r"^[0-9]+$", tld):
                report["url_features"].append({"type": "warning", "message": f"Uses an uncommon Top-Level Domain (.{tld})."})
                risk_points += 10
        
    if ml_url_length > 75:
        report["url_features"].append({"type": "warning", "message": f"URL is unusually long ({ml_url_length} chars)."})
        risk_points += 10
        
    if '@' in original_url:
        report["url_features"].append({"type": "danger", "message": "Contains '@' symbol, allowing redirect masking."})
        risk_points += 20
        
    clean_domain = re.sub(r'^www\.', '', domain_no_port)
    domain_parts = clean_domain.split('.')
    ml_num_subdomains = len(domain_parts) - 2 if len(domain_parts) > 2 else 0
    if ml_num_subdomains >= 2 and not is_ip:
        report["url_features"].append({"type": "warning", "message": f"Too many subdomains ({ml_num_subdomains+2})."})
        risk_points += 10
        
    suspicious_keywords = ['login', 'secure', 'account', 'update', 'verify', 'password', 'passwd', 'admin']
    found_keywords = [kw for kw in suspicious_keywords if kw in original_url.lower()]
    if found_keywords:
        report["url_features"].append({"type": "danger", "message": f"Contains high-risk keywords: {', '.join(found_keywords)}."})
        risk_points += 15
        
    if re.search(r'(&&|\|\||=\'|=\")', original_url):
        report["url_features"].append({"type": "danger", "message": "Suspicious characters indicative of injection/credentials passing."})
        risk_points += 20

    # ---------------------------------------------
    # 2. DOMAIN INFORMATION CHECKER (API / WHOIS)
    # ---------------------------------------------
    if not is_ip:
        try:
            w = whois.whois(domain_no_port)
            creation_date = w.creation_date
            expiration_date = w.expiration_date
            
            if type(creation_date) is list:
                creation_date = creation_date[0]
            if type(expiration_date) is list:
                expiration_date = expiration_date[0]
                
            if creation_date:
                age_days = (datetime.datetime.now() - creation_date).days
                ml_domain_age = age_days
                report["domain_info"].append({"type": "info", "message": f"Domain Created: {creation_date.strftime('%Y-%m-%d')} ({age_days} days ago)"})
                
                if age_days < 30:
                    report["domain_info"].append({"type": "danger", "message": f"Domain is newly registered! Highly suspicious."})
                    risk_points += 25
                elif age_days > 365:
                    report["domain_info"].append({"type": "success", "message": f"Domain is well-established (> 1 year)."})
                    risk_points -= 5
            else:
                report["domain_info"].append({"type": "warning", "message": "Could not verify domain creation date."})
                risk_points += 5
                
            if expiration_date:
                 report["domain_info"].append({"type": "info", "message": f"Domain Expires: {expiration_date.strftime('%Y-%m-%d')}"})
                 
            if w.registrar:
                 report["domain_info"].append({"type": "info", "message": f"Registrar: {w.registrar}"})
                 
        except Exception as e:
            report["domain_info"].append({"type": "warning", "message": "WHOIS Lookup failed (domain may not exist or blocked)."})
            risk_points += 15
    else:
        report["domain_info"].append({"type": "warning", "message": "IP address means no WHOIS registration data available."})

    # ---------------------------------------------
    # 3. SSL CERTIFICATE VERIFICATION API
    # ---------------------------------------------
    if not is_ip and domain_no_port:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain_no_port, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain_no_port) as ssock:
                    cert = ssock.getpeercert()
                    
                    issuer = dict(x[0] for x in cert['issuer'])
                    issuer_name = issuer.get('organizationName', 'Unknown Issuer')
                    
                    not_after = cert['notAfter']
                    expiry_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_left = (expiry_date - datetime.datetime.now()).days
                    
                    report["ssl_check"].append({"type": "success", "message": f"Valid SSL present. Issued by: {issuer_name}"})
                    report["ssl_check"].append({"type": "info", "message": f"Certificate Expires: {expiry_date.strftime('%Y-%m-%d')} ({days_left} days remaining)"})
                    
                    if days_left < 0:
                        report["ssl_check"].append({"type": "danger", "message": "SSL Certificate has EXPIRED!"})
                        risk_points += 20
        except Exception as e:
            report["ssl_check"].append({"type": "warning", "message": "No valid SSL certificate found."})
            if original_url.startswith('https'):
                risk_points += 20
            else:
                risk_points += 10
    else:
         report["ssl_check"].append({"type": "warning", "message": "SSL verification skipped for raw IP."})

    # ---------------------------------------------
    # 4. EXTERNAL THREAT API (URLHaus Abuse.ch API)
    # ---------------------------------------------
    try:
        urlhaus_req = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=4)
        if urlhaus_req.status_code == 200:
            urlhaus_data = urlhaus_req.json()
            if urlhaus_data.get("query_status") == "ok":
                threat_type = urlhaus_data.get("threat", "Malware/Phishing")
                report["api_reports"].append({"type": "danger", "message": f"URLHaus API: Flagged as Malicious ({threat_type})."})
                risk_points += 50
                ml_is_blacklisted = 1
            elif urlhaus_data.get("query_status") == "no_results":
                report["api_reports"].append({"type": "success", "message": "URLHaus API: Not found in active Threat Databases. Domain is currently clean."})
            else:
                report["api_reports"].append({"type": "success", "message": "URLHaus API: No malicious activity reported."})
    except Exception:
         report["api_reports"].append({"type": "warning", "message": "URLHaus Threat API was unreachable."})

    # ---------------------------------------------
    # 5. WEBSITE CONTENT ANALYSIS
    # ---------------------------------------------
    try:
        req = requests.get(url, timeout=3, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(req.text, 'html.parser')
        
        password_inputs = soup.find_all('input', type='password')
        if password_inputs:
             report["content_analysis"].append({"type": "warning", "message": "Credential Harvesting: Password login form detected!"})
             if risk_points >= 20: 
                 risk_points += 25  # Very bad if domain is young AND has a login form
        else:
             report["content_analysis"].append({"type": "success", "message": "No obvious password input fields detected."})
             
        if req.history:
              report["content_analysis"].append({"type": "warning", "message": f"Website performed {len(req.history)} redirects."})
              risk_points += (len(req.history) * 2)
              
    except Exception as e:
        report["content_analysis"].append({"type": "warning", "message": "Could not securely fetch website HTML contents."})
        risk_points += 5

    # ---------------------------------------------
    # 6. ML DETECTION MODEL CALCULATION
    # ---------------------------------------------
    if ML_MODEL:
        features = np.array([[ml_url_length, ml_domain_age, ml_num_subdomains, ml_has_https, ml_is_blacklisted]])
        prediction = ML_MODEL.predict(features)[0]
        confidence_probs = ML_MODEL.predict_proba(features)[0]
        confidence = int(max(confidence_probs) * 100)
        
        if prediction == 1:
            report["ml_prediction"] = {"prediction": "Phishing", "confidence": f"{confidence}%", "type": "danger"}
            risk_points += 20
        else:
            report["ml_prediction"] = {"prediction": "Legitimate", "confidence": f"{confidence}%", "type": "success"}
    else:
        report["ml_prediction"] = {"prediction": "Model Offline", "confidence": "N/A", "type": "warning"}

    # ---------------------------------------------
    # 7. FINAL RISK SCORE & CLASSIFICATION
    # ---------------------------------------------
    final_score = max(0, min(100, risk_points))
    
    if final_score >= 60:
        status = "Phishing / Malicious"
    elif final_score >= 30:
        status = "Suspicious"
    else:
        status = "Legitimate"
        
    report["score"] = final_score
    report["status"] = status
    
    return report
