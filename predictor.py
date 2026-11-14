"""
ScamShield AI - multilingual message analysis.

Important:
- The ML model is trained on the English SMS Spam Collection dataset.
- Kannada/Hindi/English phrase detection below is rule-based support.
- This is a screening aid, not proof that a message is safe or fraudulent.
"""

import re
from pathlib import Path

import joblib


MODEL_PATH = Path(__file__).resolve().parent / "models" / "message_model.pkl"

try:
    MODEL = joblib.load(MODEL_PATH)
except Exception:
    MODEL = None


# Patterns are deliberately phrase-based. Add new examples as you collect
# verified local scam messages. Detection cannot cover every wording or dialect.
WARNING_PATTERNS = {
    "OTP or verification-code request": [
        r"\botp\b", r"\bone time password\b", r"\bverification code\b",
        r"\bshare (?:the )?(?:code|otp)\b", r"\bsend (?:the )?(?:code|otp)\b",
        r"\bcode (?:bhejo|batao|share karo)\b",
        r"\botp (?:bhejo|batao|share karo|kodu|kalisu)\b",
        r"ಒಟಿಪಿ", r"ಓಟಿಪಿ", r"ಒಟಿಪಿ\s*(?:ಹೇಳಿ|ಕಳುಹಿಸಿ|ಹಂಚಿಕೊಳ್ಳಿ)",
        r"ಒಟಿಪಿ\s*(?:ಕೊಡಿ|ತಿಳಿಸಿ)",
        r"ओटीपी", r"ओ\s*टी\s*पी", r"ओटीपी\s*(?:भेजें|बताएं|बताओ|शेयर करें)",
        r"(?:otp|code)\s*(?:bhejo|batao|share karo|karo)",
    ],
    "UPI PIN or payment-authorisation request": [
        r"\bupi\b.{0,35}\bpin\b", r"\bpin\b.{0,35}\bupi\b",
        r"\benter your pin\b", r"\bapprove (?:the )?collect request\b",
        r"\bscan (?:the )?qr\b", r"\bpayment request\b",
        r"ಯುಪಿಐ", r"ಯುಪಿಐ\s*ಪಿನ್", r"ಪಿನ್\s*(?:ನಮೂದಿಸಿ|ಹೇಳಿ|ಕಳುಹಿಸಿ)",
        r"ಕ್ಯೂಆರ್\s*ಕೋಡ್", r"ಹಣ\s*(?:ಕಳುಹಿಸಿ|ಪಾವತಿಸಿ)",
        r"यूपीआई", r"यूपीआई\s*पिन", r"पिन\s*(?:डालें|बताएं|भेजें)",
        r"क्यूआर\s*कोड", r"पैसे\s*(?:भेजें|जमा करें)",
        r"\bupi pin\b", r"\bqr code scan\b",
    ],
    "Bank details or card information request": [
        r"\baccount number\b", r"\bcard number\b", r"\bcvv\b",
        r"\bexpiry date\b", r"\bdebit card\b", r"\bcredit card\b",
        r"\bnet banking\b", r"\bbank details\b",
        r"ಬ್ಯಾಂಕ್\s*(?:ಖಾತೆ|ವಿವರ)", r"ಖಾತೆ\s*(?:ಸಂಖ್ಯೆ|ವಿವರ)",
        r"ಡೆಬಿಟ್\s*ಕಾರ್ಡ್", r"ಕ್ರೆಡಿಟ್\s*ಕಾರ್ಡ್", r"ಸಿವಿವಿ",
        r"बैंक\s*(?:खाता|विवरण)", r"खाता\s*(?:नंबर|संख्या|विवरण)",
        r"डेबिट\s*कार्ड", r"क्रेडिट\s*कार्ड", r"सीवीवी",
    ],
    "KYC update or document-verification pressure": [
        r"\bkyc\b", r"\bupdate your (?:bank )?details\b",
        r"\bkyc (?:update|verification|expire|expired)\b",
        r"ಕೆವೈಸಿ", r"ಕೆವೈಸಿ\s*(?:ನವೀಕರಿಸಿ|ಪೂರ್ಣಗೊಳಿಸಿ)",
        r"ಆಧಾರ್\s*(?:ಸಂಖ್ಯೆ|ವಿವರ)", r"ಪ್ಯಾನ್\s*(?:ಕಾರ್ಡ್|ಸಂಖ್ಯೆ)",
        r"केवाईसी", r"के\s*वाई\s*सी", r"केवाईसी\s*(?:अपडेट|पूरा|सत्यापन)",
        r"आधार\s*(?:नंबर|विवरण)", r"पैन\s*(?:कार्ड|नंबर)",
    ],
    "Account-blocking or suspension threat": [
        r"\baccount\b.{0,35}\b(?:blocked|suspended|disabled|closed)\b",
        r"\b(?:blocked|suspended|disabled)\b.{0,35}\baccount\b",
        r"\baccount will be blocked\b", r"\baccount will be closed\b",
        r"ಖಾತೆ.{0,35}(?:ನಿರ್ಬಂಧ|ಬ್ಲಾಕ್|ಮುಚ್ಚು)",
        r"(?:ಖಾತೆ|ಸಿಮ್).{0,35}(?:ನಿಲ್ಲಿಸಲಾಗುತ್ತದೆ|ರದ್ದಾಗುತ್ತದೆ|ಮುಚ್ಚಲಾಗುತ್ತದೆ)",
        r"खाता.{0,35}(?:बंद|ब्लॉक|निलंबित)",
        r"(?:खाता|सिम).{0,35}(?:बंद हो जाएगा|बंद कर दिया जाएगा)",
        r"(?:account|sim).{0,35}(?:block aguttade|close aguttade)",
    ],
    "Prize, lottery or unexpected-reward claim": [
        r"\b(?:you have won|winner|lottery|claim your prize|lucky draw)\b",
        r"\bprize money\b", r"\bcongratulations\b.{0,40}\bprize\b",
        r"ಲಾಟರಿ", r"ಬಹುಮಾನ", r"ನೀವು\s*ಗೆದ್ದಿದ್ದೀರಿ",
        r"ಬಹುಮಾನ\s*(?:ಪಡೆಯಿರಿ|ಕ್ಲೈಮ್)",
        r"लॉटरी", r"इनाम", r"पुरस्कार", r"आपने\s*(?:जीत|जीता) लिया",
        r"आप\s*(?:विजेता|लकी विजेता)",
    ],
    "Advance-fee or payment-to-receive-money request": [
        r"\bpay (?:a )?(?:small )?(?:fee|charge|tax) to receive\b",
        r"\bprocessing fee\b", r"\bregistration fee\b",
        r"\bpay first\b", r"\bdeposit (?:money|amount)\b",
        r"ಮುಂಗಡ\s*(?:ಹಣ|ಪಾವತಿ)", r"ಮೊದಲು\s*ಹಣ\s*(?:ಕಳುಹಿಸಿ|ಪಾವತಿಸಿ)",
        r"ಶುಲ್ಕ\s*ಪಾವತಿಸಿ", r"ಹಣ\s*ಜಮಾ\s*ಮಾಡಿ",
        r"पहले\s*(?:पैसे|रकम)\s*(?:भेजें|जमा करें)",
        r"प्रोसेसिंग\s*फीस", r"रजिस्ट्रेशन\s*फीस",
        r"शुल्क\s*(?:जमा|भुगतान)\s*करें",
    ],
    "Urgent action or fear-based pressure": [
        r"\bact now\b", r"\bimmediately\b", r"\burgent\b",
        r"\blast warning\b", r"\bwithin \d+ hours?\b",
        r"ತಕ್ಷಣ", r"ಕೂಡಲೇ", r"ಇಂದೇ\s*(?:ಮಾಡಿ|ಪಾವತಿಸಿ)",
        r"ತಕ್ಷಣವೇ", r"ಇಲ್ಲದಿದ್ದರೆ",
        r"तुरंत", r"शीघ्र", r"अभी", r"आज ही", r"वरना",
        r"नहीं तो", r"तुरंत कार्रवाई",
    ],
    "Suspicious link or request to open a link": [
        r"https?://", r"\bwww\.", r"\bclick (?:here|the link)\b",
        r"\bopen this link\b", r"\bverify at\b",
        r"ಲಿಂಕ್\s*(?:ಕ್ಲಿಕ್|ತೆರೆಯಿರಿ)", r"ಈ\s*ಲಿಂಕ್",
        r"लिंक\s*(?:पर क्लिक|खोलें)", r"इस लिंक",
    ],
    "Remote-access app or screen-sharing request": [
        r"\banydesk\b", r"\bteamviewer\b", r"\bremote access\b",
        r"\bscreen sharing\b", r"\binstall this app\b",
        r"ಸ್ಕ್ರೀನ್\s*ಶೇರ್", r"ರಿಮೋಟ್\s*ಆಕ್ಸೆಸ್",
        r"ऐनीडेस्क", r"टीमव्यूअर", r"रिमोट\s*एक्सेस",
        r"स्क्रीन\s*शेयर",
    ],
}


def _normalise(text):
    """Lowercase and collapse whitespace without removing Indian scripts."""
    return re.sub(r"\s+", " ", str(text or "").lower()).strip()


def detect_warning_signs(message):
    """Return human-readable warning categories found in a message."""
    text = _normalise(message)
    if not text:
        return []

    found = []
    for category, patterns in WARNING_PATTERNS.items():
        for pattern in patterns:
            try:
                if re.search(pattern, text, flags=re.IGNORECASE):
                    found.append(category)
                    break
            except re.error:
                # A malformed optional pattern should not crash message scanning.
                continue
    return found


def detect_script(message):
    """Identify the scripts present; this does not identify the language perfectly."""
    text = str(message or "")
    has_kannada = bool(re.search(r"[\u0C80-\u0CFF]", text))
    has_devanagari = bool(re.search(r"[\u0900-\u097F]", text))
    has_latin = bool(re.search(r"[A-Za-z]", text))

    scripts = []
    if has_kannada:
        scripts.append("Kannada script")
    if has_devanagari:
        scripts.append("Devanagari script (often Hindi)")
    if has_latin:
        scripts.append("Latin script (English or transliteration)")
    return ", ".join(scripts) if scripts else "No recognised script detected"


def _model_spam_probability(message):
    """Get the English SMS model probability where the saved model supports it."""
    if MODEL is None:
        return None

    try:
        if hasattr(MODEL, "predict_proba"):
            probabilities = MODEL.predict_proba([message])[0]
            classes = list(getattr(MODEL, "classes_", []))
            if not classes:
                return float(max(probabilities)) * 100

            # Most common UCI labels are 'ham' and 'spam'.
            spam_index = next(
                (i for i, label in enumerate(classes)
                 if str(label).strip().lower() == "spam"),
                None,
            )
            if spam_index is not None:
                return float(probabilities[spam_index]) * 100
            return float(max(probabilities)) * 100

        prediction = str(MODEL.predict([message])[0]).strip().lower()
        return 85.0 if prediction == "spam" else 15.0
    except Exception:
        return None


def analyze_message(message):
    """
    Analyze one SMS/message and return the fields used by ScamShield's app.py.

    Risk score is a screening score, not a calibrated fraud probability.
    Multilingual phrase matches raise the score even if the English-only
    machine-learning model gives a low score.
    """
    cleaned = str(message or "").strip()
    if not cleaned:
        raise ValueError("Message cannot be empty.")

    warnings = detect_warning_signs(cleaned)
    model_probability = _model_spam_probability(cleaned)

    # Start with the English ML model only when it is available.
    if model_probability is None:
        score = 0.0
    else:
        score = max(0.0, min(100.0, model_probability))

    # Add conservative rule-based risk for high-signal scam requests.
    high_signal = {
        "OTP or verification-code request",
        "UPI PIN or payment-authorisation request",
        "Bank details or card information request",
        "Remote-access app or screen-sharing request",
    }
    medium_signal = {
        "KYC update or document-verification pressure",
        "Account-blocking or suspension threat",
        "Advance-fee or payment-to-receive-money request",
        "Prize, lottery or unexpected-reward claim",
        "Suspicious link or request to open a link",
    }

    if any(item in high_signal for item in warnings):
        score = max(score, 75.0)
    if any(item in medium_signal for item in warnings):
        score = max(score, 55.0)
    if len(warnings) >= 2:
        score = max(score, 80.0)
    if len(warnings) >= 3:
        score = max(score, 90.0)

    score = int(round(max(0.0, min(100.0, score))))
    prediction = "Spam" if score >= 50 else "Ham"

    return {
        "prediction": prediction,
        "risk_score": score,
        "spam_probability": score,
        "warning_signs": warnings,
        "warning_detected": bool(warnings),
        "script_indicator": detect_script(cleaned),
        "model_probability": (
            None if model_probability is None
            else round(float(model_probability), 2)
        ),
        "model_note": (
            "English SMS model plus multilingual phrase rules"
            if model_probability is not None
            else "Multilingual phrase rules only; ML model unavailable"
        ),
    }
