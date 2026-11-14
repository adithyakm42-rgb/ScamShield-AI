# 🛡️ ScamShield AI

**Detect. Analyse. Protect.**

ScamShield AI is an educational digital-safety screening prototype. It checks website URL patterns and uses a machine-learning model to estimate whether an SMS resembles spam. It is not a bank security system or a verified fraud-detection service.

## Features

- **URL screening:** checks URL structure, HTTP vs HTTPS, IP-address hosts, shortened domains, punycode labels, unusual ports, sensitive wording and gambling/betting-related wording.
- **AI message screening:** TF-IDF + Logistic Regression model trained on the UCI SMS Spam Collection.
- **Readable dashboard:** high-contrast light theme, summary metrics and simple navigation.
- **SQLite history:** stores scans locally, with search, filters and CSV export.
- **Safety guide:** practical advice for protecting personal and financial information.

## Important limitations

- The URL scanner works offline. It does not open submitted links or query a live phishing/reputation database.
- URL scores are heuristic caution scores, not probabilities of fraud.
- Gambling/betting words are category indicators, not proof that a website is fraudulent.
- Advertising parameters such as `click_id`, `sub_id` and `utm_source` are common tracking fields; their presence alone does not prove a scam.
- The message model estimates similarity to spam in its training dataset. It does not confirm financial fraud.
- A low score does not mean a URL or message is safe.

Never enter passwords, OTPs, UPI PINs, card details or other secrets into this app.

## Project structure

```text
ScamShield-AI/
├── app.py
├── url_scanner.py
├── predictor.py
├── database.py
├── train_message.py
├── requirements.txt
├── README.md
├── .gitignore
├── models/
│   └── message_model.pkl
├── dataset/
│   └── SMSSpamCollection
└── tests/
    ├── test_url_scanner.py
    ├── test_predictor.py
    └── test_database.py
```

## Setup on Windows (PowerShell)

1. Install Python 3.11 or newer.
2. Open this project folder in VS Code.
3. Create and activate a virtual environment:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

4. Install dependencies:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

5. Start the app:

   ```powershell
   python -m streamlit run app.py
   ```

The browser should open at `http://localhost:8501`.

## Run tests

```powershell
python -m unittest discover -s tests -v
```

## Retrain the message model (optional)

The repository includes a trained model. To retrain it:

```powershell
python train_message.py
```

The script downloads the UCI dataset only if `dataset/SMSSpamCollection` is missing, trains the model and saves `models/message_model.pkl`.

## Dataset acknowledgement

The SMS Spam Collection is provided by the UCI Machine Learning Repository:
https://archive.ics.uci.edu/dataset/228/sms+spam+collection

Cite the dataset in academic or public presentations and review its original terms before redistributing it.

## GitHub publishing

Before publishing, inspect the files and ensure no private data, credentials, local database, virtual environment or personal information is included.

```powershell
git init
git add .
git status
git commit -m "Initial release: ScamShield AI"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/ScamShield-AI.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username. If a remote already exists, check it with `git remote -v` before adding another.

## License

Add a project license before allowing reuse. The dataset and third-party dependencies retain their own terms.
