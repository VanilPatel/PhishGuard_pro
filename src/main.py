import os
import re
from urllib.parse import urlparse
try:
    from ml_detector import MLPhishingDetector
except ImportError:
    MLPhishingDetector = None

def detect_obfuscation(email_content):
    score = 0
    findings = []
    # Check for zero-width spaces or other invisible character obfuscation commonly used to bypass scanners
    invisible_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
    found_chars = [char for char in invisible_chars if char in email_content]
    if found_chars:
        score += 30
        findings.append("🚩 Obfuscation detected: Invisible characters (e.g., zero-width spaces) found in the email body.")
        
    return score, findings

def analyze_urls(email_content):
    score = 0
    findings = []
    
    # Extract URLs
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_content)
    
    if not urls:
        return score, findings
        
    for url in urls:
        try:
            parsed = urlparse(url if url.startswith('http') else f"http://{url}")
            domain = parsed.netloc.lower()
            
            # 1. Suspicious IP Addresses (already mostly handled, but good to have in URL logic)
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                score += 40
                findings.append(f"🚩 Suspicious URL: Uses an IP address instead of a domain name ({url}).")
                
            # 2. URL Shorteners
            shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'cli.gs', 'shorte.st']
            if any(shortener in domain for shortener in shorteners):
                score += 25
                findings.append(f"🚩 Obfuscated URL: Uses a URL shortener service ({domain}).")
                
            # 3. Homograph Attack (Cyrillic mixing)
            if re.search(r'[а-яА-Я]', domain):
                score += 50
                findings.append(f"🚩 CRITICAL: Homograph attack detected in URL ({domain}). Mixing scripts to spoof legitimate domains.")
                
            # 4. Deep Subdomains (e.g., login.microsoft.security.update.com)
            if domain.count('.') > 3:
                score += 15
                findings.append(f"🚩 Suspicious URL: Unusually high number of subdomains ({domain}).")
                
        except Exception:
            pass

    return score, findings

def simple_scanner(email_content):
    score = 0
    findings = []

    # 1. Check for Social Engineering Keywords
    keywords = ['urgent', 'suspended', 'verify', 'login', 'bank', 'immediately', 'action required', 'account compromised', 'unauthorized access', 'validate your account']
    for word in keywords:
        if word in email_content.lower():
            score += 15
            findings.append(f"🚩 High-pressure/social engineering keyword detected: '{word}'")

    # 2. Advanced Obfuscation Checks
    obf_score, obf_findings = detect_obfuscation(email_content)
    score += obf_score
    findings.extend(obf_findings)

    # 3. Advanced URL Analysis
    url_score, url_findings = analyze_urls(email_content)
    score += url_score
    findings.extend(url_findings)

    # 4. Check for typical phishing "Sense of Urgency"
    if "24 hours" in email_content or "limited time" in email_content:
        score += 20
        findings.append("🚩 Time-sensitive threat detected.")

    return score, findings

def run_project():
    print("--- 🛡️ PhishGuard Pro Email Scanner 🛡️ ---")
    
    # Path to your test data
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'sample_mail.txt')
    
    if not os.path.exists(data_path):
        print(f"Error: Please create the file {data_path} first.")
        return

    with open(data_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Rule-Based Analysis
    print("\n[+] Running Rule-Based Heuristics Check...")
    score, findings = simple_scanner(content)
    
    # Machine Learning Analysis
    ml_verdict = "N/A"
    ml_probability = 0.0
    if MLPhishingDetector:
        print("\n[+] Running Machine Learning Semantic Analysis...")
        ml_detector = MLPhishingDetector()
        
        if ml_detector.model_loaded:
            try:
                # We utilize the extract and predict methodology exported by ml_detector
                prediction, ml_prob, _ = ml_detector.predict(content)
                
                if prediction == 1:
                    ml_verdict = f"PHISHING (Confidence: {ml_prob*100:.2f}%)"
                    score += 50  # Boost overall score if ML detects it
                    findings.append(f"🤖 ML Engine Flagged Content as Malicious (Conf: {ml_prob*100:.2f}%)")
                elif prediction == 0:
                    ml_verdict = f"BENIGN (Confidence: {ml_prob*100:.2f}%)"
            except Exception as e:
                findings.append(f"🤖 ML Engine encountered error: {e}")

    print(f"\nScanning content from: {data_path}")
    print("-" * 50)
    
    if findings:
        for finding in findings:
            print(finding)
    else:
        print("✅ No suspicious indicators found in the scan.")
        
    print("-" * 50)
    
    # Final Risk Assessment
    if score >= 50:
        print(f"FINAL VERDICT: ⚠️ HIGH RISK (Rule Score: {score})")
    elif score >= 20:
        print(f"FINAL VERDICT: ⚠️ MEDIUM RISK (Rule Score: {score})")
    else:
        print(f"FINAL VERDICT: ✅ LOW RISK (Rule Score: {score})")
    
    print(f"ML ENGINE VERDICT: {ml_verdict}")

if __name__ == "__main__":
    print("Script started...")
    try:
        run_project()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()