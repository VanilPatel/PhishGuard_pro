import pickle
import os
import re
from urllib.parse import urlparse

class MLPhishingDetector:
    def __init__(self):
        """Load the trained ML model"""
        try:
            # Try multiple path options
            model_paths = [
                os.path.join(os.path.dirname(__file__), '..', 'models', 'phish_model.pkl'),
                'models/phish_model.pkl',
                '../models/phish_model.pkl',
                os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models', 'phish_model.pkl'))
            ]
            
            model_path = None
            for path in model_paths:
                if os.path.exists(path):
                    model_path = path
                    break
            
            if model_path is None:
                print(f"❌ Model not found in any of these paths:")
                for p in model_paths:
                    print(f"   - {os.path.abspath(p)}")
                self.model_loaded = False
                return
            
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            self.model_loaded = True
            print(f"✅ ML Model loaded successfully from {model_path}")
        except Exception as e:
            print(f"❌ Error loading ML model: {e}")
            self.model_loaded = False
            self.model = None
    
    def extract_features(self, email_text):
        """
        Extract 48 numerical features from email text to match training data.
        Enhanced: If a URL is present, parse it to fill in more features.
        """
        from urllib.parse import urlparse
        features = {}
        urls = re.findall(r'https?://[^\s]+', email_text)
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        suspicious_keywords = ['urgent', 'verify', 'confirm', 'update', 'suspended', 'clicked', 'click here']
        brands = ['google', 'microsoft', 'amazon', 'paypal', 'apple', 'bank']
        # Use the first URL for feature extraction if present
        url = urls[0] if urls else ''
        parsed = urlparse(url) if url else None
        # SubdomainLevel: count dots in netloc minus 1 (for domain.tld)
        subdomain_level = 0
        if parsed and parsed.hostname:
            subdomain_level = parsed.hostname.count('.') - 1 if parsed.hostname.count('.') > 1 else 0
        # PathLevel: number of path segments
        path_level = 0
        if parsed and parsed.path:
            path_level = len([p for p in parsed.path.split('/') if p])
        # NumDashInHostname
        num_dash_in_hostname = parsed.hostname.count('-') if parsed and parsed.hostname else 0
        # HostnameLength
        hostname_length = len(parsed.hostname) if parsed and parsed.hostname else 0
        # PathLength
        path_length = len(parsed.path) if parsed and parsed.path else 0
        # QueryLength
        query_length = len(parsed.query) if parsed and parsed.query else 0
        # DoubleSlashInPath
        double_slash_in_path = 1 if parsed and '//' in parsed.path else 0
        # HttpsInHostname
        https_in_hostname = 1 if parsed and 'https' in parsed.hostname else 0 if parsed and parsed.hostname else 0
        # DomainInSubdomains
        domain_in_subdomains = 1 if parsed and parsed.hostname and any(brand in parsed.hostname for brand in brands) else 0
        # DomainInPaths
        domain_in_paths = 1 if parsed and any(brand in parsed.path for brand in brands) else 0
        # Fill all 48 features in order
        features_list = [
            email_text.count('.'), # NumDots
            subdomain_level, # SubdomainLevel
            path_level, # PathLevel
            max([len(url) for url in urls], default=0), # UrlLength
            email_text.count('-'), # NumDash
            num_dash_in_hostname, # NumDashInHostname
            1 if '@' in email_text else 0, # AtSymbol
            1 if '~' in email_text else 0, # TildeSymbol
            email_text.count('_'), # NumUnderscore
            email_text.count('%'), # NumPercent
            sum(url.count('?') for url in urls), # NumQueryComponents
            sum(url.count('&') for url in urls), # NumAmpersand
            sum(url.count('#') for url in urls), # NumHash
            sum(1 for c in email_text if c.isdigit()), # NumNumericChars
            0 if 'https://' in email_text else 1, # NoHttps
            0, # RandomString
            1 if re.search(ip_pattern, email_text) else 0, # IpAddress
            domain_in_subdomains, # DomainInSubdomains
            domain_in_paths, # DomainInPaths
            https_in_hostname, # HttpsInHostname
            hostname_length, # HostnameLength
            path_length, # PathLength
            query_length, # QueryLength
            double_slash_in_path, # DoubleSlashInPath
            sum(1 for keyword in suspicious_keywords if keyword in email_text.lower()), # NumSensitiveWords
            1 if any(brand in email_text.lower() for brand in brands) else 0, # EmbeddedBrandName
            0, # PctExtHyperlinks
            0, # PctExtResourceUrls
            0, # ExtFavicon
            1 if 'form' in email_text.lower() and 'http://' in email_text and not 'https://' in email_text else 0, # InsecureForms
            0, # RelativeFormAction
            0, # ExtFormAction
            1 if 'form' in email_text.lower() and re.search(ip_pattern, email_text) else 0, # AbnormalFormAction
            1 if 'javascript:' in email_text.lower() or 'onclick=' in email_text.lower() else 0, # PctNullSelfRedirectHyperlinks
            0, # FrequentDomainNameMismatch
            0, # FakeLinkInStatusBar
            0, # RightClickDisabled
            0, # PopUpWindow
            0, # SubmitInfoToEmail
            0, # IframeOrFrame
            0, # MissingTitle
            0, # ImagesOnlyInForm
            0, # SubdomainLevelRT
            0, # UrlLengthRT
            0, # PctExtResourceUrlsRT
            0, # AbnormalExtFormActionR
            0, # ExtMetaScriptLinkRT
            0, # PctExtNullSelfRedirectHyperlinksRT
        ]
        return features_list
    
    def predict(self, email_text):
        """
        Get ML prediction for email
        Returns: (prediction, confidence, features_dict)
        prediction: 1 = Phishing, 0 = Legitimate
        confidence: 0-1 confidence score
        """
        if not self.model_loaded:
            return None, 0, None
        
        try:
            # Extract features (guaranteed 48 features in correct order)
            features_list = self.extract_features(email_text)
            prediction = self.model.predict([features_list])[0]
            probability = self.model.predict_proba([features_list])[0]
            confidence = probability[int(prediction)]
            return prediction, confidence, dict(enumerate(features_list))
            
        except Exception as e:
            print(f"Error in ML prediction: {e}")
            return None, 0, None
