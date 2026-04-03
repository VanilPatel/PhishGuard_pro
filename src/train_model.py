import pandas as pd
import pickle
import os
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
import sys
sys.path.append(os.path.dirname(__file__))
from ml_detector import MLPhishingDetector

def train_phishing_model(data_path):
    """
    Train a machine learning model to detect phishing URLs/emails
    Uses numerical features extracted from URL and HTML structure
    """
    
    print("📂 Loading dataset...")
    
    # Check if file exists (handle double .csv extension)
    if not os.path.exists(data_path):
        # Try with .csv.csv extension
        alt_path = data_path.replace('.csv', '.csv.csv')
        if os.path.exists(alt_path):
            data_path = alt_path
            print(f"⚠️  Using {alt_path}")
        else:
            print(f"❌ Error: Dataset not found at {data_path}")
            return False
    
    try:
        # Load dataset
        df = pd.read_csv(data_path, encoding='utf-8')
        print(f"✅ Loaded {len(df)} samples")
        
        # Display column names
        print(f"\n📋 Available columns: {list(df.columns)}")
        
        feature_matrix = []
        labels = []
        
        # Scenario C: 100k Email Dataset with 'raw_text' and 'label' (0/1)
        if 'raw_text' in df.columns and 'label' in df.columns:
            print("📝 Detected massive 100k+ Email Dataset! Extracting 48 Advanced ML features from raw text...")
            detector = MLPhishingDetector()
            
            # Since this dataset is huge, we'll take a balanced sample to train efficiently
            # or we can train on all. Let's process 15,000 for speed but high accuracy.
            sample_size = min(len(df), 20000)
            df = df.sample(n=sample_size, random_state=42).dropna(subset=['raw_text', 'label'])
            print(f"🔄 Processing {len(df)} samples for advanced feature extraction...")
            
            for idx, row in df.iterrows():
                text = str(row['raw_text'])
                label = int(row['label'])
                feats = detector.extract_features(text)
                feature_matrix.append(feats)
                labels.append(label)
                
            X = pd.DataFrame(feature_matrix)
            y = pd.Series(labels)
            
        # Scenario A: If we are dealing with pure text dataset like spam.csv
        elif 'Message' in df.columns and 'Category' in df.columns:
            print("📝 Detected text-based dataset. Extracting 48 Advanced ML features from raw text...")
            detector = MLPhishingDetector() # Load feature logic
            df = df.dropna(subset=['Message', 'Category'])
            for idx, row in df.iterrows():
                text = str(row['Message'])
                label = 1 if str(row['Category']).lower() == 'spam' else 0
                feats = detector.extract_features(text)
                feature_matrix.append(feats)
                labels.append(label)
                
            X = pd.DataFrame(feature_matrix)
            y = pd.Series(labels)
            
        else:
            # Find label column (Scenario B: Pre-extracted features)
            label_col = None
            for col in ['CLASS_LABEL', 'label', 'Label', 'category', 'Category']:
                if col in df.columns:
                    label_col = col
                    break
            
            if not label_col:
                print(f"❌ Error: Could not find label column")
                return False
            
            print(f"🏷️  Using '{label_col}' as target label")
            
            # Remove the ID column if it exists
            if 'id' in df.columns:
                df = df.drop('id', axis=1)
            
            X = df.drop(label_col, axis=1)
            y = df[label_col]
        
        print(f"✅ Features shape: {X.shape}")
        print(f"   - Samples: {X.shape[0]}")
        print(f"   - Features: {X.shape[1]}")
        
        # 2. Split data (80% training, 20% testing)
        print("\n✂️  Splitting data (80% train, 20% test)...")
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # 3. Train Random Forest Model (better for numerical features)
        print("\n🧠 Training Random Forest model...")
        model = RandomForestClassifier(n_estimators=150, max_depth=25, random_state=42, n_jobs=-1)
        model.fit(X_train, y_train)
        
        # 4. Evaluate the Model
        print("\n📊 Model Performance:")
        train_pred = model.predict(X_train)
        test_pred = model.predict(X_test)
        
        train_acc = accuracy_score(y_train, train_pred)
        test_acc = accuracy_score(y_test, test_pred)
        precision = precision_score(y_test, test_pred, zero_division=0)
        recall = recall_score(y_test, test_pred, zero_division=0)
        
        print(f"   Training Accuracy: {train_acc:.2%}")
        print(f"   Testing Accuracy:  {test_acc:.2%}")
        print(f"   Precision:         {precision:.2%}")
        print(f"   Recall:            {recall:.2%}")
        
        # 5. Save the Model
        print("\n💾 Saving highly-accurate custom trained model...")
        
        # Create models directory if it doesn't exist
        os.makedirs(os.path.join(os.path.dirname(__file__), '..', 'models'), exist_ok=True)
        model_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'phish_model.pkl')
        
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        print("✅ Custom threat-model payload mapped and saved successfully!")
        print(f"   📁 {model_path}")
        return True
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"❌ Error during training: {e}")
        return False

if __name__ == "__main__":
    train_phishing_model(os.path.join(os.path.dirname(__file__), "safe_augmented_threats.csv"))

if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  PHISHING EMAIL DETECTOR - MODEL TRAINING")
    print("=" * 60 + "\n")
    
    # Updated path to go up one directory to data/
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'Phishing_Email.csv')
    
    success = train_phishing_model(data_path)
    
    if success:
        print("\n" + "=" * 60)
        print("✅ Ready to use the model in app.py!")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("⚠️  Please download the dataset and try again")
        print("=" * 60)
