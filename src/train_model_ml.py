import pandas as pd
import pickle
import os
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score

def train_text_phishing_model():
    """
    Train a text-based ML model using the numerical dataset
    Creates synthetic text examples from numerical features
    """
    
    print("📂 Loading dataset...")
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'Phishing_Email.csv')
    
    if not os.path.exists(data_path):
        alt_path = data_path.replace('.csv', '.csv.csv')
        if os.path.exists(alt_path):
            data_path = alt_path
    
    try:
        df = pd.read_csv(data_path, encoding='utf-8')
        print(f"✅ Loaded {len(df)} samples")
        
        # For this dataset, we'll use feature importance approach
        # Since we don't have raw text, we'll use the numerical features directly with a better model
        
        # Remove ID column
        if 'id' in df.columns:
            df = df.drop('id', axis=1)
        
        # Find label column
        label_col = 'CLASS_LABEL'
        X = df.drop(label_col, axis=1)
        y = df[label_col]
        
        print(f"✅ Features shape: {X.shape}")
        print(f"   - Samples: {X.shape[0]}")
        print(f"   - Features: {X.shape[1]}")
        
        # Split data
        print("\n✂️  Splitting data (80% train, 20% test)...")
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Train model
        print("\n🧠 Training Random Forest model...")
        model = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
        model.fit(X_train, y_train)
        
        # Evaluate
        print("\n📊 Model Performance:")
        test_pred = model.predict(X_test)
        
        test_acc = accuracy_score(y_test, test_pred)
        precision = precision_score(y_test, test_pred, zero_division=0)
        recall = recall_score(y_test, test_pred, zero_division=0)
        
        print(f"   Testing Accuracy:  {test_acc:.2%}")
        print(f"   Precision:         {precision:.2%}")
        print(f"   Recall:            {recall:.2%}")
        
        # Save model
        print("\n💾 Saving model...")
        os.makedirs(os.path.join(os.path.dirname(__file__), '..', 'models'), exist_ok=True)
        model_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'phish_model.pkl')
        feature_names_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'feature_names.pkl')
        
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        # Save feature names for later use
        with open(feature_names_path, 'wb') as f:
            pickle.dump(list(X.columns), f)
        
        print("✅ Model trained and saved successfully!")
        print(f"   📁 {model_path}")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  PHISHING DETECTOR - ML MODEL TRAINING")
    print("=" * 60 + "\n")
    
    train_text_phishing_model()
