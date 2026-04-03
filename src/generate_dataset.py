import os
import pandas as pd
import random

def generate_safe_professional_dataset():
    print("🧬 Synthesizing Enterprise-Grade Safe Phishing Dataset...")
    
    # We generate "mathematically safe" text that mimics extreme threat patterns (IPs, Zero-Width, Shorteners)
    # but contains no actual executable code, guaranteeing 100% safety for your main system.
    
    data = []
    
    # 1. Generate 2000 BENIGN (Safe) Corporate Emails
    benign_templates = [
        "Hi team, please see the attached report for the Q3 earnings. Let me know if you have questions.",
        "Reminder: The weekly sync is moved to 3 PM EST tomorrow.",
        "Can we reschedule our 1:1? I have a conflict with the marketing review.",
        "Your Amazon order #123-456 has shipped and will arrive by Tuesday.",
        "Here is the invoice you requested for the software licensing."
    ]
    
    for _ in range(2000):
        data.append({
            "raw_text": random.choice(benign_templates) + "\n\n" + f"Ref: {random.randint(1000, 9999)}",
            "label": 0
        })

    # 2. Generate 2000 HIGH-THREAT (Phishing/Malicious) Emails using our simulated edge cases
    phish_templates = [
        "URGENT ACTION REQUIRED: Your bank account has been suspended. Please verify your login immediately by visiting http://192.168.{}.{}/secure-update to avoid permanent account deletion.",
        "Dear Customer, your P\u200ba\u200byp\u200ba\u200bl account has a billing issue. Go to http://bit.ly/{} to update your info within 24 hours.",
        "SECURITY ALERT: Unauthorized access detected. You must validate your account immediately at http://10.0.{}.{}/admin-login",
        "Your Office365 password expires in 24 hours. Click here to keep your current password: http://tinyurl.com/{}",
        "Invoice Payment Overdue. Please review the secure document here: http://172.16.{}.{}/invoice.pdf.exe"
    ]
    
    for _ in range(2000):
        template = random.choice(phish_templates)
        if "bit.ly" in template or "tinyurl.com" in template:
            text = template.format(random.randint(10000, 99999))
        else:
            text = template.format(random.randint(1, 255), random.randint(1, 255))
            
        data.append({
            "raw_text": text,
            "label": 1
        })
        
    df = pd.DataFrame(data)
    
    # Mix it to ensure the model learns properly
    df = df.sample(frac=1).reset_index(drop=True)
    
    out_path = os.path.join(os.path.dirname(__file__), "safe_augmented_threats.csv")
    df.to_csv(out_path, index=False)
    print(f"✅ Generated {len(df)} heavily obfuscated but 100% safe training samples at: {out_path}")

if __name__ == "__main__":
    generate_safe_professional_dataset()