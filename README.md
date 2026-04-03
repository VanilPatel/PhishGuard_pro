# PhishGuard Pro: Advanced Email Phishing Detector
## Features

- Hybrid phishing detection: rule-based + machine learning
- Streamlit web UI with color-coded badges, summary verdict, and progress bar
- File upload (.txt/.eml), sidebar, and extracted features table
- Batch scanning: upload CSV of emails for bulk analysis
- PDF report download for single and batch scans
- Scan logging (CSV) with user consent
- Language detection (warns for non-English emails)
- Input validation and error handling

## Usage

1. Install dependencies: `pip install -r requirements.txt`
2. Run the app: `streamlit run src/app.py`
3. Paste or upload an email to scan, or use the batch scan feature in the sidebar

## Data

- Uses `data/Phishing_Email.csv` for model training

## Model

- Trained RandomForestClassifier on 48 features

## Folder Structure

```
README.md
requirements.txt
train_model.py
data/
   Phishing_Email.csv
models/
src/
   app.py
   ml_detector.py
   train_model.py
```
   ```
   Then open [http://localhost:8501](http://localhost:8501)

## File Structure
- `src/app.py` - Streamlit web app
- `src/ml_detector.py` - ML feature extraction and prediction
- `src/train_model.py` - Model training script
- `models/` - Saved ML model
- `data/` - Dataset folder

## Notes
- Do **not** commit your dataset or model files to GitHub (see `.gitignore`).
- For best results, use a real phishing dataset and retrain the model.

## License
MIT
