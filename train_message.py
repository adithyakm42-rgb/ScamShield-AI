"""Train the SMS spam classifier using the UCI SMS Spam Collection."""
import csv
import urllib.request
import zipfile
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "dataset"
MODEL_DIR = ROOT / "models"
DATA_FILE = DATA_DIR / "SMSSpamCollection"
ZIP_FILE = DATA_DIR / "sms.zip"
MODEL_FILE = MODEL_DIR / "message_model.pkl"
DATA_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"

def main():
    DATA_DIR.mkdir(exist_ok=True)
    MODEL_DIR.mkdir(exist_ok=True)

    if not DATA_FILE.exists():
        print("Downloading UCI SMS Spam Collection...")
        urllib.request.urlretrieve(DATA_URL, ZIP_FILE)
        with zipfile.ZipFile(ZIP_FILE) as archive:
            member = next(
                name for name in archive.namelist()
                if name.endswith("SMSSpamCollection")
            )
            with archive.open(member) as source, DATA_FILE.open("wb") as target:
                target.write(source.read())

    messages, labels = [], []
    with DATA_FILE.open("r", encoding="utf-8") as file:
        reader = csv.reader(file, delimiter="\\t")
        for row in reader:
            if len(row) == 2 and row[0] in {"ham", "spam"}:
                messages.append(row[1])
                labels.append(1 if row[0] == "spam" else 0)

    if not messages:
        raise RuntimeError("Dataset is empty or has an unexpected format.")

    x_train, x_test, y_train, y_test = train_test_split(
        messages, labels, test_size=0.2, random_state=42, stratify=labels
    )
    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2), max_features=20000, sublinear_tf=True
        )),
        ("classifier", LogisticRegression(
            max_iter=1000, class_weight="balanced"
        )),
    ])
    print(f"Training on {len(x_train)} messages...")
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print(classification_report(
        y_test, predictions, target_names=["Normal", "Spam"]
    ))
    joblib.dump(model, MODEL_FILE)
    print(f"Saved trained model to: {MODEL_FILE}")

if __name__ == "__main__":
    main()
