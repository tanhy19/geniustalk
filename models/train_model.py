# models/train_model.py
# ML Model Training Script
# Trains a Naive Bayes + TF-IDF classifier on real SMS spam dataset
# Saves trained model to models/scam_classifier.pkl

import os
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
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

DATASET_PATH = "datasets/sms_spam.csv"
MODEL_PATH   = "models/scam_classifier.pkl"
REPORT_PATH  = "models/training_report.json"


# ─────────────────────────────────────────
# STEP 1 — LOAD DATASET
# ─────────────────────────────────────────

def load_dataset():
    """
    Loads the SMS spam dataset.
    Dataset has 2 columns: label (ham/spam) and message text.
    """
    print("Loading dataset...")

    df = pd.read_csv(
        DATASET_PATH,
        sep='\t',
        header=None,
        names=['label', 'message'],
        encoding='utf-8'
    )

    print(f"Total messages loaded: {len(df)}")
    print(f"Spam messages : {len(df[df['label'] == 'spam'])}")
    print(f"Ham messages  : {len(df[df['label'] == 'ham'])}")

    return df


# ─────────────────────────────────────────
# STEP 2 — PREPARE DATA
# ─────────────────────────────────────────

def prepare_data(df):
    """
    Prepares data for training.
    - Converts labels to binary (spam=1, ham=0)
    - Cleans text
    - Splits into train/test sets
    """
    print("\nPreparing data...")

    # Convert labels to binary
    # spam = 1 (scam), ham = 0 (safe)
    df['label_binary'] = df['label'].map({'spam': 1, 'ham': 0})

    # Basic text cleaning
    df['message'] = df['message'].str.lower()
    df['message'] = df['message'].str.strip()

    # Split features and labels
    X = df['message']
    y = df['label_binary']

    # 80% training, 20% testing
    # random_state=42 ensures same split every time
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y  # keeps spam/ham ratio balanced in both sets
    )

    print(f"Training set size : {len(X_train)}")
    print(f"Testing set size  : {len(X_test)}")

    return X_train, X_test, y_train, y_test


# ─────────────────────────────────────────
# STEP 3 — BUILD AND TRAIN MODEL
# ─────────────────────────────────────────

def train_model(X_train, y_train):
    """
    Builds and trains the ML pipeline.

    Pipeline:
    1. TF-IDF Vectorizer — converts text to numbers
       - Looks at single words AND pairs of words (ngram_range=(1,2))
       - Ignores very common words like 'the', 'is', 'at'
       - Keeps top 10000 most important features

    2. Multinomial Naive Bayes — the classifier
       - Works extremely well for text classification
       - Fast to train, good accuracy on spam detection
       - alpha=0.1 reduces over-fitting
    """
    print("\nBuilding model pipeline...")

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 2),      # single words + word pairs
            max_features=10000,      # top 10000 features
            stop_words='english',    # ignore common words
            min_df=2,                # word must appear at least twice
            sublinear_tf=True        # apply log normalization
        )),
        ('classifier', MultinomialNB(alpha=0.1))
    ])

    print("Training model...")
    pipeline.fit(X_train, y_train)
    print("Training complete!")

    return pipeline


# ─────────────────────────────────────────
# STEP 4 — EVALUATE MODEL
# ─────────────────────────────────────────

def evaluate_model(pipeline, X_test, y_test):
    """
    Tests the model on unseen data and prints performance metrics.

    Key metrics:
    - Accuracy  : overall correct predictions
    - Precision : when it says scam, how often is it right
    - Recall    : of all real scams, how many did it catch
    - F1 Score  : balance between precision and recall
    """
    print("\nEvaluating model...")

    y_pred = pipeline.predict(X_test)

    accuracy  = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall    = recall_score(y_test, y_pred)
    f1        = f1_score(y_test, y_pred)
    cm        = confusion_matrix(y_test, y_pred)

    print("\n" + "="*50)
    print(" MODEL PERFORMANCE REPORT")
    print("="*50)
    print(f" Accuracy  : {accuracy:.4f}  ({accuracy*100:.2f}%)")
    print(f" Precision : {precision:.4f}  ({precision*100:.2f}%)")
    print(f" Recall    : {recall:.4f}  ({recall*100:.2f}%)")
    print(f" F1 Score  : {f1:.4f}  ({f1*100:.2f}%)")
    print("="*50)
    print("\n Confusion Matrix:")
    print(f"              Predicted Safe  Predicted Scam")
    print(f" Actual Safe  {cm[0][0]:^14}  {cm[0][1]:^14}")
    print(f" Actual Scam  {cm[1][0]:^14}  {cm[1][1]:^14}")
    print("="*50)
    print("\n Full Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Scam']))

    metrics = {
        "accuracy" : round(accuracy, 4),
        "precision": round(precision, 4),
        "recall"   : round(recall, 4),
        "f1_score" : round(f1, 4),
        "confusion_matrix": cm.tolist(),
        "total_test_samples": len(y_test),
        "correct_predictions": int(sum(y_pred == y_test))
    }

    return metrics


# ─────────────────────────────────────────
# STEP 5 — SAVE MODEL
# ─────────────────────────────────────────

def save_model(pipeline, metrics):
    """Saves the trained model and training report to disk."""
    print("\nSaving model...")

    # Save the trained pipeline
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(pipeline, f)
    print(f"Model saved to: {MODEL_PATH}")

    # Save training report as JSON (useful for your FYP report)
    with open(REPORT_PATH, 'w') as f:
        json.dump(metrics, f, indent=2)
    print(f"Training report saved to: {REPORT_PATH}")


# ─────────────────────────────────────────
# STEP 6 — TEST WITH SAMPLE MESSAGES
# ─────────────────────────────────────────

def test_sample_messages(pipeline):
    """
    Tests the trained model with sample messages.
    Shows confidence scores for each prediction.
    """
    print("\n" + "="*50)
    print(" SAMPLE MESSAGE PREDICTIONS")
    print("="*50)

    test_messages = [
        # Should be SCAM
        "URGENT! You won RM10,000! Send bank details now!",
        "Congratulations! You have been selected for a prize. Click here to claim.",
        "Your account will be suspended. Verify immediately at bit.ly/verify",
        "FREE entry to win! Text WIN to 80086 now!!!",
        "WINNER! You have been chosen. Call now to claim your reward.",

        # Should be SAFE
        "Hey are you free tomorrow for lunch?",
        "Can you pick up milk on the way home?",
        "Meeting at 3pm today, dont forget",
        "Happy birthday! Hope you have a great day",
        "The report is ready, I'll send it over now"
    ]

    for msg in test_messages:
        # Get prediction
        prediction = pipeline.predict([msg])[0]
        # Get confidence probability
        proba = pipeline.predict_proba([msg])[0]
        confidence = proba[1] if prediction == 1 else proba[0]
        confidence_pct = round(confidence * 100, 1)

        label  = "SCAM" if prediction == 1 else "SAFE"
        symbol = "🚨" if prediction == 1 else "✅"

        print(f"{symbol} [{label}] ({confidence_pct}%) — {msg[:60]}")

    print("="*50)


# ─────────────────────────────────────────
# MAIN — RUN FULL TRAINING PIPELINE
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("="*50)
    print(" GENIUSTALK ML MODEL TRAINING")
    print("="*50)

    # Install pandas if needed
    try:
        import pandas as pd
    except ImportError:
        print("Installing pandas...")
        os.system("pip install pandas")
        import pandas as pd

    # Run full pipeline
    df                              = load_dataset()
    X_train, X_test, y_train, y_test = prepare_data(df)
    pipeline                        = train_model(X_train, y_train)
    metrics                         = evaluate_model(pipeline, X_test, y_test)
    save_model(pipeline, metrics)
    test_sample_messages(pipeline)

    print("\n✅ Training complete! Model ready to use.")
    print(f"   Model file : {MODEL_PATH}")
    print(f"   Report file: {REPORT_PATH}")