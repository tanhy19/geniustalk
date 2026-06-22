# models/train_model.py
# Combined ML Training Script
# Trains both models in one run:
# 1. YOUR model   — Naive Bayes + TF-IDF (scam_classifier.pkl)
# 2. FRIEND model — Logistic Regression  (model.pkl + vectorizer.pkl)

import os
import json
import pickle
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# ─────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────

MAIN_DATASET_CSV    = "datasets/main_dataset.csv"
CUSTOM_PHISHING_CSV = "datasets/custom_phishing.csv"

YOUR_MODEL_PATH     = "models/scam_classifier.pkl"
YOUR_REPORT_PATH    = "models/training_report.json"
FRIEND_MODEL_PATH   = "models/model.pkl"
FRIEND_VEC_PATH     = "models/vectorizer.pkl"


# ─────────────────────────────────────────
# YOUR MODEL — NAIVE BAYES
# ─────────────────────────────────────────

def train_your_model():
    print("\n" + "="*55)
    print(" TRAINING YOUR MODEL (Naive Bayes + TF-IDF)")
    print("="*55)

    # ── Load dataset ──
    print("Loading sms_spam.csv...")
    df = pd.read_csv(MAIN_DATASET_CSV, encoding='latin-1')
    df.columns = ['label', 'message']

    print(f"Total messages : {len(df)}")
    print(f"Spam           : {len(df[df['label'] == 'spam'])}")
    print(f"Ham            : {len(df[df['label'] == 'ham'])}")

    # ── Prepare data ──
    df['label_binary'] = df['label'].map({
        'phishing': 1, 'spam': 1,
        'safe': 0, 'ham': 0
    })
    df['message']      = df['message'].str.lower().str.strip()

    X = df['message']
    y = df['label_binary']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    print(f"Training set   : {len(X_train)}")
    print(f"Testing set    : {len(X_test)}")

    # ── Build pipeline ──
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=10000,
            stop_words='english',
            min_df=2,
            sublinear_tf=True
        )),
        ('classifier', MultinomialNB(alpha=0.1))
    ])

    # ── Train ──
    print("Training...")
    pipeline.fit(X_train, y_train)

    # ── Evaluate ──
    y_pred    = pipeline.predict(X_test)
    accuracy  = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall    = recall_score(y_test, y_pred)
    f1        = f1_score(y_test, y_pred)
    cm        = confusion_matrix(y_test, y_pred)

    print("\n" + "="*55)
    print(" YOUR MODEL PERFORMANCE")
    print("="*55)
    print(f" Accuracy  : {accuracy*100:.2f}%")
    print(f" Precision : {precision*100:.2f}%")
    print(f" Recall    : {recall*100:.2f}%")
    print(f" F1 Score  : {f1*100:.2f}%")
    print("="*55)
    print(f"\n Confusion Matrix:")
    print(f"               Predicted Safe  Predicted Scam")
    print(f" Actual Safe   {cm[0][0]:^14}  {cm[0][1]:^14}")
    print(f" Actual Scam   {cm[1][0]:^14}  {cm[1][1]:^14}")
    print("\n" + classification_report(
        y_test, y_pred, target_names=['Safe', 'Scam']
    ))

    # ── Save model ──
    with open(YOUR_MODEL_PATH, 'wb') as f:
        pickle.dump(pipeline, f)

    metrics = {
        "accuracy"         : round(accuracy, 4),
        "precision"        : round(precision, 4),
        "recall"           : round(recall, 4),
        "f1_score"         : round(f1, 4),
        "confusion_matrix" : cm.tolist(),
        "total_test_samples" : len(y_test),
        "correct_predictions": int(sum(y_pred == y_test))
    }
    with open(YOUR_REPORT_PATH, 'w') as f:
        json.dump(metrics, f, indent=2)

    print(f"✅ Your model saved to  : {YOUR_MODEL_PATH}")
    print(f"✅ Training report saved: {YOUR_REPORT_PATH}")

    return pipeline


# ─────────────────────────────────────────
# FRIEND'S MODEL — LOGISTIC REGRESSION
# ─────────────────────────────────────────

def train_friend_model():
    print("\n" + "="*55)
    print(" TRAINING FRIEND'S MODEL (Logistic Regression)")
    print("="*55)

    # ── Load spam.csv ──
    try:
        df1 = pd.read_csv(MAIN_DATASET_CSV, encoding="latin-1")
        df1 = df1.iloc[:, :2]
        df1.columns = ["label", "text"]
        df1["label"] = df1["label"].replace({
            "spam": "phishing",
            "ham" : "safe"
        })
        print(f"spam.csv loaded         : {len(df1)} rows")
    except Exception as e:
        print(f"Error loading spam.csv  : {e}")
        df1 = pd.DataFrame(columns=["label", "text"])

    # ── Load custom_phishing.csv ──
    try:
        df2         = pd.read_csv(CUSTOM_PHISHING_CSV, encoding="latin-1")
        df2.columns = [c.lower().strip() for c in df2.columns]

        if "label" not in df2.columns or "text" not in df2.columns:
            cols = list(df2.columns)
            df2  = df2.rename(columns={cols[0]: "label", cols[1]: "text"})

        df2         = df2[["label", "text"]]
        df2_boosted = pd.concat([df2] * 10, ignore_index=True)
        print(f"custom_phishing.csv loaded: {len(df2)} rows")
        print(f"custom_phishing.csv boosted: {len(df2_boosted)} rows")

    except Exception as e:
        print(f"Error loading custom_phishing.csv: {e}")
        df2_boosted = pd.DataFrame(columns=["label", "text"])

    # ── Combine ──
    df = pd.concat([df1, df2_boosted], ignore_index=True)
    df = df.dropna(subset=["text", "label"])

    print(f"\nCombined dataset: {len(df)} rows")
    print(f"Label counts:\n{df['label'].value_counts()}")

    # ── Train ──
    X            = df["text"]
    y            = df["label"]
    vectorizer   = TfidfVectorizer()
    X_vectorized = vectorizer.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_vectorized, y,
        test_size=0.2,
        random_state=42
    )

    print("\nTraining...")
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    accuracy    = accuracy_score(y_test, predictions)

    print("\n" + "="*55)
    print(" FRIEND'S MODEL PERFORMANCE")
    print("="*55)
    print(f" Accuracy: {accuracy*100:.2f}%")
    print("\n" + classification_report(y_test, predictions))

    # ── Save ──
    with open(FRIEND_MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    with open(FRIEND_VEC_PATH, "wb") as f:
        pickle.dump(vectorizer, f)

    print(f"✅ YY's model saved to : {FRIEND_MODEL_PATH}")
    print(f"✅ Vectorizer saved to     : {FRIEND_VEC_PATH}")

    return model, vectorizer


# ─────────────────────────────────────────
# SAMPLE TEST — BOTH MODELS
# ─────────────────────────────────────────

def test_both_models(your_pipeline, friend_model, friend_vectorizer):
    print("\n" + "="*55)
    print(" SAMPLE PREDICTIONS — BOTH MODELS")
    print("="*55)

    test_messages = [
        ("SCAM", "URGENT! You won RM10,000! Send bank details now!"),
        ("SCAM", "Congratulations! You have been selected for a prize."),
        ("SCAM", "Your account will be suspended. Verify immediately."),
        ("SCAM", "FREE entry to win! Text WIN to 80086 now!!!"),
        ("SAFE", "Hey are you free tomorrow for lunch?"),
        ("SAFE", "Can you pick up milk on the way home?"),
        ("SAFE", "Meeting at 3pm today, dont forget"),
        ("SAFE", "Happy birthday! Hope you have a great day"),
    ]

    print(f"\n{'Message':<45} {'Expected':<8} {'Your':<8} {'Friend':<8}")
    print("-" * 75)

    for expected, msg in test_messages:
        # Your model prediction
        your_pred  = your_pipeline.predict([msg.lower()])[0]
        your_label = "SCAM" if your_pred == 1 else "SAFE"

        # Friend's model prediction
        vec         = friend_vectorizer.transform([msg.lower()])
        friend_pred = friend_model.predict(vec)[0]
        friend_label = "SCAM" if friend_pred == "phishing" else "SAFE"

        # Match indicators
        your_match   = "✅" if your_label   == expected else "❌"
        friend_match = "✅" if friend_label == expected else "❌"

        print(f"{msg[:44]:<45} {expected:<8} "
              f"{your_label}{your_match:<6} {friend_label}{friend_match:<6}")

    print("="*55)


# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("="*55)
    print(" GENIUSTALK — COMBINED ML TRAINING")
    print("="*55)
    print(" This trains both models:")
    print("   1. Your Naive Bayes scam classifier")
    print("   2. Friend's Logistic Regression phishing model")
    print("="*55)

    # Train both models
    your_pipeline               = train_your_model()
    friend_model, friend_vec    = train_friend_model()

    # Test both together
    test_both_models(your_pipeline, friend_model, friend_vec)

    print("\n✅ All models trained successfully!")
    print(f"   Your model    : {YOUR_MODEL_PATH}")
    print(f"   Friend model  : {FRIEND_MODEL_PATH}")
    print(f"   Friend vector : {FRIEND_VEC_PATH}")
    print(f"   Training report: {YOUR_REPORT_PATH}")