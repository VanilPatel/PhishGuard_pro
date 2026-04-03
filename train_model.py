import pandas as pd
import pickle
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix

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
        df = pd.read_csv(data_path)
        print(f"✅ Loaded {len(df)} samples")
        
        # Display column names
        print(f"\n📋 Available columns: {len(df.columns)} features")
        
        # Find label column (try different naming conventions)
        label_col = None
        for col in ['CLASS_LABEL', 'label', 'Label', 'category', 'Category']:
            if col in df.columns:
                label_col = col
                break
        
        if not label_col:
            print(f"❌ Error: Could not find label column")
            print(f"Available columns: {list(df.columns)[:10]}...")
            return False
        
        print(f"🏷️  Using '{label_col}' as target label")
        
        # Remove the ID column if it exists
        if 'id' in df.columns:
            df = df.drop('id', axis=1)
        
        # Separate features and labels
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
        model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
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
        print("\n💾 Saving model...")
        
        # Create models directory if it doesn't exist
        os.makedirs('models', exist_ok=True)
        
        with open('models/phish_model.pkl', 'wb') as f:
            pickle.dump(model, f)
        
        print("✅ Model trained and saved successfully!")
        
        print("✅ Model trained and saved successfully!")
        print("   📁 models/phish_model.pkl")
        return True
        
    except Exception as e:
        print(f"❌ Error during training: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  PHISHING EMAIL DETECTOR - MODEL TRAINING")
    print("=" * 60 + "\n")
    
    data_path = 'data/Phishing_Email.csv'
    
    success = train_phishing_model(data_path)
    
    if success:
        print("\n" + "=" * 60)
        print("✅ Ready to use the model in app.py!")
        print("=" * 60)
    else:
        print("\n" + "=" * 60)
        print("⚠️  Please download the dataset and try again")
        print("=" * 60)
