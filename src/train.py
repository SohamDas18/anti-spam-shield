import os
import sys
import joblib
import pandas as pd
import numpy as np

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import VotingClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from src.preprocessing import clean_text

DATASET_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'dataset', 'spam.csv')
MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'model')

def train_models():
    print("=== Training Spam Mail Detection & Email Risk Analysis Model ===")

    # 1. Load Dataset
    if not os.path.exists(DATASET_PATH):
        print("Dataset not found. Generating dataset first...")
        from dataset.generate_dataset import generate_spam_dataset
        generate_spam_dataset(DATASET_PATH)

    df = pd.read_csv(DATASET_PATH)
    print(f"Loaded {len(df)} records from {DATASET_PATH}")
    print("Class distribution:\n", df['label'].value_counts())

    # 2. Preprocess text
    print("Preprocessing text messages...")
    df['cleaned_message'] = df['message'].apply(clean_text)
    
    # Map labels: ham -> 0, spam -> 1
    df['target'] = df['label'].map({'ham': 0, 'spam': 1})

    X = df['cleaned_message']
    y = df['target']

    # 3. Train-Test Split (80/20 stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 4. TF-IDF Feature Extraction
    print("Fitting TF-IDF Vectorizer...")
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        sublinear_tf=True
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # 5. Train Ensemble Classifier (MultinomialNB + LogisticRegression)
    print("Training classifiers...")
    nb_model = MultinomialNB(alpha=0.1)
    lr_model = LogisticRegression(max_iter=1000, C=2.0)
    
    ensemble = VotingClassifier(
        estimators=[('nb', nb_model), ('lr', lr_model)],
        voting='soft'
    )
    ensemble.fit(X_train_vec, y_train)

    # 6. Evaluation
    y_pred = ensemble.predict(X_test_vec)
    y_proba = ensemble.predict_proba(X_test_vec)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("\n--- Model Performance Results ---")
    print(f"Accuracy  : {acc * 100:.2f}%")
    print(f"Precision : {prec * 100:.2f}%")
    print(f"Recall    : {rec * 100:.2f}%")
    print(f"F1-Score  : {f1 * 100:.2f}%")
    print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=['HAM', 'SPAM']))

    # 7. Train Secondary URL Risk Model
    # Features: [length, dots, special_chars, has_ip, is_https, kw_count, dangerous_ext]
    print("Training URL Risk Assessment calibrator...")
    np.random.seed(42)
    sample_url_features = np.array([
        [22, 1, 0, 0, 1, 0, 0],  # google.com (safe)
        [35, 1, 2, 0, 1, 0, 0],  # normal link
        [95, 4, 8, 1, 0, 3, 0],  # IP phishing
        [110, 3, 6, 0, 1, 2, 1], # Malware .exe
        [85, 3, 5, 0, 0, 2, 0],  # Fake login
        [18, 1, 0, 0, 1, 0, 0],  # Wikipedia
        [120, 5, 10, 1, 0, 4, 1] # High risk malware IP
    ])
    sample_url_labels = np.array([0, 0, 1, 1, 1, 0, 1])
    risk_rf = RandomForestClassifier(n_estimators=50, random_state=42)
    risk_rf.fit(sample_url_features, sample_url_labels)

    # 8. Save Serialized Artifacts
    os.makedirs(MODEL_DIR, exist_ok=True)
    spam_model_path = os.path.join(MODEL_DIR, 'spam_model.pkl')
    vectorizer_path = os.path.join(MODEL_DIR, 'vectorizer.pkl')
    risk_model_path = os.path.join(MODEL_DIR, 'risk_model.pkl')

    joblib.dump(ensemble, spam_model_path)
    joblib.dump(vectorizer, vectorizer_path)
    joblib.dump(risk_rf, risk_model_path)

    metrics = {
        'accuracy': round(acc * 100, 2),
        'precision': round(prec * 100, 2),
        'recall': round(rec * 100, 2),
        'f1_score': round(f1 * 100, 2)
    }
    joblib.dump(metrics, os.path.join(MODEL_DIR, 'metrics.pkl'))

    print(f"\nArtifacts saved successfully:")
    print(f" -> {spam_model_path}")
    print(f" -> {vectorizer_path}")
    print(f" -> {risk_model_path}")

    return ensemble, vectorizer, metrics

if __name__ == '__main__':
    train_models()
