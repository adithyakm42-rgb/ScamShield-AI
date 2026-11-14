"""Load the bundled SMS spam model and return a spam-likelihood estimate."""
from pathlib import Path
import joblib

MODEL_PATH = Path(__file__).resolve().parent / "models" / "message_model.pkl"
if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Trained model not found at {MODEL_PATH}. "
        "Run: python train_message.py"
    )

message_model = joblib.load(MODEL_PATH)

def analyze_message(message):
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Message must not be empty.")

    probabilities = message_model.predict_proba([message])[0]
    classes = list(message_model.classes_)
    # The training script encodes spam as 1; locate class 1 explicitly.
    spam_index = classes.index(1) if 1 in classes else len(probabilities) - 1
    spam_probability = float(probabilities[spam_index])
    risk_score = round(spam_probability * 100, 2)

    if risk_score >= 70:
        prediction = "High Risk - Spam-like Message"
    elif risk_score >= 40:
        prediction = "Medium Risk - Suspicious Message"
    else:
        prediction = "Low Risk - Less Spam-like"

    return {
        "prediction": prediction,
        "risk_score": risk_score,
        "spam_probability": risk_score,
    }
