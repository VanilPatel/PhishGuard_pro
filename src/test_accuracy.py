import os
import sys

# Ensure we can import our modules
sys.path.append(os.path.dirname(__file__))
from ml_detector import MLPhishingDetector
from main import simple_scanner

def run_simulated_tests():
    print("=" * 60)
    print("🛡️ SAFE THREAT SIMULATOR: TESTING CAPABILITIES 🛡️")
    print("=" * 60)
    
    # Load our Machine Learning Engine
    detector = MLPhishingDetector()
    
    if not detector.model_loaded:
        print("❌ Error: ML Model not loaded.")
        return

    # Safe, simulated test text strings (harmless to your PC, but look like threats to the model)
    test_cases = [
        {
            "name": "1. Normal Corporate Email (Benign)",
            "content": "Hi Zack,\n\nFollowing up on our onboarding tasks. Can you please review the attached PDF and let me know if the documentation makes sense?\n\nThanks,\nSarah",
            "expected": "BENIGN"
        },
        {
            "name": "2. Blatant IP-Based Phishing (High Risk)",
            "content": "URGENT ACTION REQUIRED: Your bank account has been suspended due to unauthorized access. Please verify your login immediately by visiting http://192.168.10.50/secure-update to avoid permanent account deletion.",
            "expected": "PHISHING"
        },
        {
            "name": "3. Stealthy Obfuscation & URL Shortener (High Risk)",
            "content": "Dear Customer, your P\u200ba\u200byp\u200ba\u200bl account has a billing issue. Go to http://bit.ly/secure-auth-882 to update your info within 24 hours.",
            "expected": "PHISHING"
        }
    ]

    for test in test_cases:
        print(f"\n[+] Executing {test['name']}")
        print(f"    Payload: {test['content'][:80]}...")
        
        # 1. Test the Rule-Based Scanner
        score, findings = simple_scanner(test['content'])
        
        # 2. Test the Machine Learning Engine
        ml_pred, ml_conf, _ = detector.predict(test['content'])
        ml_verdict = "MALICIOUS (PHISHING)" if ml_pred == 1 else "BENIGN"
        
        # Output Results
        print(f"    [Rules Engine] Score: {score}")
        for finding in findings:
            print(f"       -> {finding}")
            
        print(f"    [ML Engine] Prediction: {ml_verdict} at {ml_conf*100:.2f}% confidence")
        
        if (ml_pred == 1 and test['expected'] == "PHISHING") or (ml_pred == 0 and test['expected'] == "BENIGN"):
            print("    ✅ TEST PASSED - Model correctly identified the threat level!")
        else:
            print("    ❌ TEST FAILED - Model misclassified this payload.")

if __name__ == "__main__":
    run_simulated_tests()