
# 🛡️ ScamShield AI

### AI-Powered SMS and URL Scam Detection System

ScamShield AI is a beginner-friendly cybersecurity project that helps users identify suspicious SMS messages and potentially unsafe URLs using machine learning and rule-based analysis.

## 🚀 Features

- **SMS Scam Detection:** Classifies messages as spam-like or normal using a trained machine learning model.
- **URL Risk Analysis:** Checks URLs for suspicious patterns and risk indicators.
- **Risk Scoring:** Displays a risk score and risk level.
- **Warning Details:** Explains why a message or URL was flagged.
- **Scan History:** Stores previous scans using SQLite.
- **Analytics Dashboard:** Displays scan statistics.
- **User-Friendly Interface:** Built with Streamlit.

## 🧰 Technologies Used

- Python
- Streamlit
- Scikit-learn
- TF-IDF Vectorization
- Logistic Regression
- SQLite
- Joblib

## 📁 Project Structure

```text
ScamShield-AI/
│
├── app.py
├── url_scanner.py
├── predictor.py
├── train_message.py
├── database.py
├── requirements.txt
├── README.md
├── LICENSE_NOTE.txt
│
├── dataset/
│   └── SMSSpamCollection
│
├── models/
│   ├── message_model.pkl
│   └── MODEL_INFO.txt
│
└── tests/
    ├── __init__.py
    ├── test_database.py
    ├── test_predictor.py
    └── test_url_scanner.py
```

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/adithyakm42-rgb/ScamShield-AI.git
```

### 2. Open the project folder

```bash
cd ScamShield-AI
```

### 3. Create a virtual environment

```bash
python -m venv .venv
```

### 4. Activate the environment

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 5. Install dependencies

```bash
python -m pip install -r requirements.txt
```

## ▶️ Run the Application

```bash
python -m streamlit run app.py
```

Open the local URL displayed in your terminal, usually:

```text
http://localhost:8501
```

## 🧠 Machine Learning

The SMS detection component uses:

- TF-IDF for text feature extraction.
- Logistic Regression for classification.
- A trained model saved using Joblib.
- The SMS Spam Collection dataset for training and evaluation.

## 🧪 Run Tests

```bash
python -m unittest discover -s tests -v
```

## ⚠️ Important Disclaimer

ScamShield AI is an educational screening tool. Its predictions are not a guarantee that a message or URL is safe or fraudulent.

URL analysis uses rule-based indicators and does not independently verify website ownership or live reputation. Always verify suspicious links through official sources. Never share passwords, OTPs, or banking details through untrusted links.

## 🎯 Project Objective

To demonstrate how machine learning and rule-based techniques can help users recognize suspicious digital messages and URLs.

## 👨‍💻 Developer

**Adithya K M**

Data Science Engineering Student

GitHub: https://github.com/adithyakm42-rgb

---

⭐ If you find this project useful, consider giving it a star!
