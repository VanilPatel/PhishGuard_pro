## (Removed __main__ block that caused recursion)
import streamlit as st
import io
import base64
from langdetect import detect, LangDetectException
import re
import requests
from urllib.parse import urlparse
from ml_detector import MLPhishingDetector

# --- Initialize ML Model ---
@st.cache_resource(show_spinner=False)
def load_ml_model():
    return MLPhishingDetector()

ml_detector = load_ml_model()

# --- LIVE THREAT INTELLIGENCE (GOOGLE SAFE BROWSING) ---
def check_google_safe_browsing(urls, api_key):
    """Hits the Google Safe Browsing API directly to verify actual real-world threats."""
    if not urls or not api_key:
        return []
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "phishguard-enterprise",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls]
        }
    }
    
    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if "matches" in data:
                return [match["threat"]["url"] for match in data["matches"]]
    except Exception as e:
        import streamlit as st
        st.error(f"Live API Error: {e}")
    
    return []

# --- 1. THE SECURITY ENGINE ---
def analyze_security(text, sender_email="", google_api_key=""):
    score = 0
    findings = []
    
    # BRAND MAPPING: Official keywords vs Official domains
    brand_map = {
        "google": ["google.com", "gmail.com", "youtube.com"],
        "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com"],
        "paypal": ["paypal.com", "paypal-objects.com"],
        "amazon": ["amazon.com", "aws.amazon.com"]
    }

    # Extract all URLs
    urls = re.findall(r'(https?://[^\s]+)', text)
    found_domains = [urlparse(u).netloc.lower() for u in urls]

    # CHECK 1: Brand vs. Link Mismatch
    for brand, trusted_domains in brand_map.items():
        if brand in text.lower():
            if urls:
                is_match = any(any(td in fd for td in trusted_domains) for fd in found_domains)
                if not is_match:
                    score += 45
                    findings.append(f"🚨 **Brand Mismatch:** Mentions **{brand.capitalize()}** but links lead to: `{found_domains}`")

    # CHECK 2: Sender Spoofing
    if sender_email:
        sender_domain = sender_email.split('@')[-1].lower()
        for brand, trusted_domains in brand_map.items():
            if brand in sender_domain and sender_domain not in trusted_domains:
                score += 50
                findings.append(f"🚨 **Spoofed Sender:** `{sender_domain}` looks like **{brand.capitalize()}** but is not official.")

    # CHECK 3: IP Address URLs
    for url in urls:
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            score += 40
            findings.append(f"🛑 **Malicious Link:** IP-based URL detected: `{url}`")

    # CHECK 4: Urgency Keywords
    urgency_words = ['urgent', 'suspended', 'verify', 'immediately', 'action required']
    for word in urgency_words:
        if word in text.lower():
            score += 15
            findings.append(f"⚠️ **High-Pressure Tactics:** Indicates potential manipulation strategy using keyword: *'{word}'*")

    # --- NEW: LIVE GOOGLE SAFE BROWSING CHECK ---
    if google_api_key and urls:
        findings.append("🌐 **Live Intelligence:** Querying Google Safe Browsing database directly...")
        bad_urls = check_google_safe_browsing(urls, google_api_key)
        for bad_url in set(bad_urls):
            score += 100  # Instant critical threat
            findings.append(f"☠️ **CRITICAL GLOBAL THREAT:** Google Safe Browsing has explicitly flagged `{bad_url}` as an active malware/phishing distributor on the internet right now!")

    # --- NEW: MACHINE LEARNING PREDICTION ---
    ml_pred, ml_conf, ml_features = ml_detector.predict(text)
    # --- Combine scores ---
    # Normalize rule-based score to 0-1 (max possible: 45+50+40+15*5+25=200)
    rule_score_norm = min(score, 100) / 100.0
    ml_score_norm = ml_conf if ml_pred == 1 else (1 - ml_conf)
    # Weighted average: 60% rule-based, 40% ML
    combined_score = 0.6 * rule_score_norm + 0.4 * ml_score_norm
    combined_score = round(combined_score * 100)
    # Add findings
    if ml_pred is not None:
        if ml_pred == 1:
            findings.append(f"🔍 **Heuristic Engine Flag:** Syntactic structure matches known threat signatures ({ml_conf*100:.1f}% confidence)")
        else:
            findings.append(f"🔍 **Heuristic Engine Flag:** Indicates standard benign communication patterns ({(1-ml_conf)*100:.1f}% confidence)")
    else:
        ml_pred = None
        ml_conf = 0
    return combined_score, findings, urls, ml_pred, ml_conf

# --- 2. THE UI DASHBOARD ---
st.set_page_config(page_title="PhishGuard Pro", page_icon="🛡️", layout="wide")


# --- SUMMARY VERDICT AT TOP ---
st.title("🛡️ PhishGuard Enterprise: Threat Remediation Engine")
st.markdown("Automated Intelligence Platform for Digital Threat Eradication")



# --- SIDEBAR ---
with st.sidebar:
    st.title("PhishGuard Enterprise")
    st.markdown("""
    **Deployment Instructions:**
    - Insert raw bytecode payload or target URL.
    - Evaluate cumulative Threat Index and Heuristic signatures.
    - Export audit logs for internal SOC operations.
    """)
    st.info("Proprietary Cybersecurity Infrastructure.")
    
    st.divider()
    st.subheader("Global Threat Intelligence")
    st.markdown("Integrate Google Safe Browsing API to instantly cross-reference extracted URLs against active, real-world malware domains safely without executing them.")
    google_api_key = st.text_input("Google Safe Browsing API Key:", type="password", key="api_key_input", placeholder="Enter Google API Key (Optional)...")

    st.divider()
    st.subheader("Batch Scan (CSV)")
    batch_file = st.file_uploader("Upload CSV for Batch Scan", type=["csv"], key="batch_file")
    batch_results = None
    if batch_file is not None:
        import pandas as pd
        try:
            df_batch = pd.read_csv(batch_file, encoding='utf-8')
            # Expect columns: 'email' or 'text', optionally 'sender'
            email_col = None
            for col in df_batch.columns:
                if col.lower() in ['email', 'text', 'body']:
                    email_col = col
                    break
            sender_col = None
            for col in df_batch.columns:
                if col.lower() in ['sender', 'from', 'from_email']:
                    sender_col = col
                    break
            if email_col is None:
                st.error("CSV must have a column named 'email', 'text', or 'body'.")
            else:
                batch_results = []
                for idx, row in df_batch.iterrows():
                    email_text = str(row[email_col])
                    sender = str(row[sender_col]) if sender_col else ""
                    
                    try:
                        score, findings, urls, ml_pred, ml_conf = analyze_security(email_text, sender, google_api_key)
                    except TypeError: # Fallback just in case
                        score, findings, urls, ml_pred, ml_conf = analyze_security(email_text, sender)
                        
                    verdict = ("High Risk" if score >= 70 else "Medium Risk" if score >= 40 else "Low Risk")
                    batch_results.append({
                        'Index': idx+1,
                        'Sender': sender,
                        'Score': score,
                        'Verdict': verdict,
                        'AI_Prediction': "Phishing" if ml_pred == 1 else "Legitimate",
                        'Confidence': f"{ml_conf*100:.1f}%",
                        'Findings': "; ".join(findings)[:200]  # Truncate for table
                    })
                st.success(f"Batch scan complete: {len(batch_results)} emails scanned.")
        except Exception as e:
            st.error(f"Error reading CSV: {e}")

# Placeholder for summary verdict
summary_placeholder = st.empty()


# --- SESSION STATE FOR RESET ---
if 'sender_input' not in st.session_state:
    st.session_state['sender_input'] = ''
if 'email_input' not in st.session_state:
    st.session_state['email_input'] = ''

col1, col2 = st.columns([2, 1])

def read_any_file(file_obj, filename):
    import io
    ext = filename.split('.')[-1].lower()
    text = ""
    try:
        if ext == 'pdf':
            import PyPDF2
            reader = PyPDF2.PdfReader(file_obj)
            for page in reader.pages:
                text += page.extract_text() + "\n"
                
        elif ext in ['docx', 'doc']:
            import docx
            doc = docx.Document(file_obj)
            text = "\n".join([para.text for para in doc.paragraphs])
            
        elif ext in ['xlsx', 'xls']:
            import pandas as pd
            df = pd.read_excel(file_obj)
            text = df.to_string()
            
        elif ext in ['png', 'jpg', 'jpeg', 'bmp', 'gif', 'tiff']:
            try:
                import pytesseract
                from PIL import Image
                image = Image.open(file_obj)
                text = pytesseract.image_to_string(image)
                text += "\n[Text successfully extracted via Visual OCR Analysis]"
            except Exception:
                # Fallback: Binary Strings Analysis to fish out hidden payload links
                file_obj.seek(0)
                content = file_obj.read()
                import string, re
                printable = set(bytes(string.printable, 'ascii'))
                extracted = [chr(b) for b in content if b in printable]
                raw_text = "".join(extracted)
                words = re.findall(r'[A-Za-z0-9_/\-.:?=]{5,}', raw_text)
                text = " ".join(words)
                text += "\n[Text/Payload extracted via Hexadecimal Binary String Carving]"
                
        else:
            # Fallback for XML, HTML, LOG, CSV, TXT, JSON, SQL, etc.
            text = file_obj.read().decode("utf-8", errors="ignore")
            
    except Exception as e:
        text = f"Error extracting payload: {e}"
        
    return text

with col1:
    sender_input = st.text_input("📧 Sender's Email Address:", value=st.session_state['sender_input'], key='sender_input', placeholder="e.g., security@microsoft-verify.com")
    upload_file = st.file_uploader("Or upload any file (PDF, Image, Word, XML, EML, etc.)", key='upload_file')
    if upload_file is not None:
        email_input = read_any_file(upload_file, upload_file.name)
        # Do not assign to st.session_state['upload_file']
        st.session_state['email_input'] = email_input
    else:
        email_input = st.text_area("📄 Paste Raw Content:", value=st.session_state['email_input'], key='email_input', height=300, placeholder="Paste your log, email body, xml file, or code here...")
    analyze_btn = st.button("🔍 Run Security Scan", key='analyze_btn')
    
    def reset_form():
        st.session_state['sender_input'] = ''
        st.session_state['email_input'] = ''
        
    reset_btn = st.button("❌ Clear/Reset", key='reset_btn', on_click=reset_form)

if analyze_btn:
    # --- Input validation ---
    if not email_input or len(email_input.strip()) < 10:
        st.warning("Please paste a valid email body (at least 10 characters)!")
    else:
        # --- Language detection ---
        try:
            lang = detect(email_input)
        except LangDetectException:
            lang = 'unknown'
        if lang != 'en' and lang != 'unknown':
            st.warning(f"Detected language: {lang.upper()}. Results may be less accurate for non-English emails.")
        
        # Read API key if user typed it
        api_key_to_use = st.session_state.get('api_key_input', "")
        
        try:
            combined_score, findings, urls, ml_pred, ml_conf = analyze_security(email_input, sender_input, api_key_to_use)
        except TypeError:
            combined_score, findings, urls, ml_pred, ml_conf = analyze_security(email_input, sender_input)
            
        _, _, ml_features = ml_detector.predict(email_input)
        # --- SUMMARY VERDICT AT TOP ---
        if combined_score >= 70:
            summary_placeholder.error("🛑 **FINAL VERDICT: HIGH RISK - This email is likely phishing!**")
            st.balloons()
        elif combined_score >= 40:
            summary_placeholder.warning("⚠️ **FINAL VERDICT: MEDIUM RISK - Suspicious indicators found.**")
        else:
            summary_placeholder.success("✅ **FINAL VERDICT: LOW RISK - This email seems legitimate.**")

        with col2:
            st.subheader("🎯 Combined Risk Assessment")
            st.metric(label="Final Score", value=f"{combined_score}/100")
            st.progress(combined_score)
            if combined_score >= 70:
                st.error("🛑 CRITICAL: High Probability of Phishing (Combined)")
            elif combined_score >= 40:
                st.warning("⚠️ CAUTION: Suspicious Indicators Found (Combined)")
            else:
                st.success("✅ LOW RISK: Seems Legitimate (Combined)")
            st.divider()
            # Enhanced AI Verdict Section
            st.subheader("🔍 Advanced Heuristics Engine")
            if ml_pred is not None:
                if ml_pred == 1:
                    st.error(f"⚠️ **Engine Classification: MALICIOUS PAYLOAD**\n\n{ml_conf*100:.1f}% Confidence")
                    st.write("🚨 The heuristic scanner detected patterns strongly correlated with known threat campaigns.")
                else:
                    st.success(f"✅ **Engine Classification: BENIGN COMMUNICATION**\n\n{(1-ml_conf)*100:.1f}% Confidence")
                    st.write("✓ The heuristic scanner evaluated the structure as standard organic communication.")
            else:
                st.info("⚠️ ML Model unavailable")
        st.divider()
        st.subheader("📋 Detailed Analysis Findings")
        if not findings:
            st.info("✅ No major threats detected.")
        else:
            for f in findings:
                # Color-coded badges for findings
                if f.startswith("🚨") or f.startswith("🛑"):
                    st.error(f)
                elif f.startswith("⚠️"):
                    st.warning(f)
                elif f.startswith("✅"):
                    st.success(f)
                elif f.startswith("🤖"):
                    st.info(f)
                else:
                    st.write(f)
        with st.expander("🔗 Extracted Links (Safely Defanged)"):
            if urls:
                for u in urls:
                    defanged = u.replace("http", "hXXp").replace(".", "[.]")
                    st.code(defanged)
            else:
                st.info("No links found in email.")

        # --- Extracted Features Table ---
        with st.expander("🧬 Show Extracted ML Features"):
            import pandas as pd
            feature_names = [
                'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
                'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
                'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
                'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress',
                'DomainInSubdomains', 'DomainInPaths', 'HttpsInHostname',
                'HostnameLength', 'PathLength', 'QueryLength', 'DoubleSlashInPath',
                'NumSensitiveWords', 'EmbeddedBrandName', 'PctExtHyperlinks',
                'PctExtResourceUrls', 'ExtFavicon', 'InsecureForms', 'RelativeFormAction',
                'ExtFormAction', 'AbnormalFormAction', 'PctNullSelfRedirectHyperlinks',
                'FrequentDomainNameMismatch', 'FakeLinkInStatusBar', 'RightClickDisabled',
                'PopUpWindow', 'SubmitInfoToEmail', 'IframeOrFrame', 'MissingTitle',
                'ImagesOnlyInForm', 'SubdomainLevelRT', 'UrlLengthRT', 'PctExtResourceUrlsRT',
                'AbnormalExtFormActionR', 'ExtMetaScriptLinkRT', 'PctExtNullSelfRedirectHyperlinksRT'
            ]
            if ml_features:
                df_feat = pd.DataFrame([ml_features.values()], columns=feature_names)
                st.dataframe(df_feat, use_container_width=True)
            else:
                st.info("No features extracted.")

        # --- PDF Report Download ---
        def make_pdf_report(email_input, sender_input, combined_score, findings, ml_pred, ml_conf, lang):
            from fpdf import FPDF
            
            # Helper to strip out emojis and non-latin1 characters
            def safe_text(text):
                return text.encode('latin-1', 'replace').decode('latin-1')

            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.cell(200, 10, txt="PhishGuard Enterprise - Threat Analysis Report", ln=True, align='C')
            pdf.ln(5)
            pdf.cell(200, 10, txt=f"Origin Sender: {safe_text(sender_input)}", ln=True)
            pdf.cell(200, 10, txt=f"Document Locale Classification: {lang}", ln=True)
            pdf.cell(200, 10, txt=f"Aggregated Threat Index: {combined_score}/100", ln=True)
            prediction_txt = "MALICIOUS PAYLOAD" if ml_pred == 1 else "BENIGN"
            pdf.cell(200, 10, txt=f"Heuristic Evaluation Signature: {prediction_txt} ({ml_conf*100:.1f}%)", ln=True)
            pdf.ln(5)
            
            # Strip emoji badges and special chars for compatibility
            clean_findings = [safe_text(f.replace("🚨", "").replace("🛑", "").replace("⚠️", "").replace("✅", "").replace("🤖", "").replace("🔍", "").strip()) for f in findings]
            
            pdf.multi_cell(0, 10, txt="Diagnostic Findings:\n" + "\n".join(clean_findings))
            pdf.ln(5)
            pdf.multi_cell(0, 10, txt="Inspected Bytecode Payload:\n" + safe_text(email_input[:1000]))
            return pdf.output(dest='S').encode('latin1')

        pdf_bytes = make_pdf_report(email_input, sender_input, combined_score, findings, ml_pred, ml_conf, lang)
        b64 = base64.b64encode(pdf_bytes).decode()
        st.download_button(
            label="📄 Download PDF Report",
            data=pdf_bytes,
            file_name="phishguard_report.pdf",
            mime="application/pdf"
        )

        # --- Scan Logging (CSV) ---
        if 'scan_log' not in st.session_state:
            st.session_state['scan_log'] = []
        if st.checkbox("Consent: Log this scan (CSV)"):
            st.session_state['scan_log'].append({
                'timestamp': str(st.session_state.get('scan_time', '')),
                'sender': sender_input,
                'lang': lang,
                'score': combined_score,
                'ai_pred': 'Phishing' if ml_pred == 1 else 'Legitimate',
                'confidence': f"{ml_conf*100:.1f}%",
                'findings': "; ".join(findings)[:200]
            })
            st.success("Scan logged!")
        if st.session_state['scan_log']:
            import pandas as pd
            st.download_button(
                label="⬇️ Download Scan Log (CSV)",
                data=pd.DataFrame(st.session_state['scan_log']).to_csv(index=False).encode(),
                file_name="phishguard_scan_log.csv",
                mime="text/csv"
            )

# --- BATCH SCAN RESULTS TABLE ---
if 'batch_results' not in st.session_state:
    st.session_state['batch_results'] = None
if batch_results is not None:
    import pandas as pd
    st.session_state['batch_results'] = batch_results
    st.subheader("📊 Batch Scan Results")
    st.dataframe(pd.DataFrame(batch_results), use_container_width=True)
    # PDF download for batch
    def make_batch_pdf(batch_results):
        from fpdf import FPDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="PhishGuard Pro - Batch Scan Report", ln=True, align='C')
        pdf.ln(5)
        for row in batch_results:
            pdf.cell(200, 10, txt=f"Sender: {row['Sender']} | Score: {row['Score']} | Verdict: {row['Verdict']}", ln=True)
            pdf.cell(200, 10, txt=f"AI: {row['AI_Prediction']} ({row['Confidence']})", ln=True)
            pdf.multi_cell(0, 10, txt=f"Findings: {row['Findings']}")
            pdf.ln(2)
        return pdf.output(dest='S').encode('latin1')
    batch_pdf_bytes = make_batch_pdf(batch_results)
    st.download_button(
        label="📄 Download Batch PDF Report",
        data=batch_pdf_bytes,
        file_name="phishguard_batch_report.pdf",
        mime="application/pdf"
    )
    # Batch scan log download
    st.download_button(
        label="⬇️ Download Batch Results (CSV)",
        data=pd.DataFrame(batch_results).to_csv(index=False).encode(),
        file_name="phishguard_batch_results.csv",
        mime="text/csv"
    )