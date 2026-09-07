# 📧 Spam Mail & SMS Phone Threat Analysis System

A Machine Learning and NLP-based **Spam Mail & SMS Phone Threat Detection and Risk Analysis System** that classifies both **Emails and SMS Text Messages** as **Spam or Ham (Legitimate)**, extracts and analyzes suspicious links and phone numbers, and evaluates potential security risks associated with interacting with them.

Unlike a traditional spam filter that only detects spam text, this project provides:

* 📩 **Multi-Channel Classification**: Dual support for **Emails** and **Phone SMS Messages**
* 📊 **Spam Confidence Probability**: Calibrated probability (0% to 100%)
* 📱 **Phone Number & Carrier Forensics**:
  * Extracts embedded phone numbers and WhatsApp contact links (`wa.me`)
  * Analyzes originating country codes and jurisdictions
  * Differentiates official institutional shortcodes (e.g. `VK-HDFCBK`) from spoofed 10-digit mobile impersonations
  * Detects **Callback Scams** and **Vishing / Smishing Traps**
* 🔗 **Static URL Threat Inspection**: Analyzes lengths, IP address hosts, subdomains, HTTPS, and dangerous files (`.exe`, `.scr`)
* ⚠️ **Multi-Vector Risk Scoring**: Continuous risk percentage & 5-tier classification (**Very Low**, **Low**, **Medium**, **High**, **Critical**)
* 🛡️ **Threat Categorization**: Phishing, Credential Theft, Utility Bill Scams, KYC Frauds, Malware, and Work-from-Home Tasks
* 🔮 **Actionable Consequences**: Clear explanation of what happens if the user calls or clicks
* 💡 **Security Recommendations**: Explicit instructions (e.g., *"DO NOT CALL THE NUMBER"*, *"DO NOT ENTER CREDENTIALS"*)
* 🗄️ **Relational MySQL Database**: Schema for `users`, `emails`, `url_analysis`, and `phone_analysis` (with zero-config SQLite fallback)
* 📈 **Executive Security Dashboard**: Live visual KPIs, Chart.js telemetry, and searchable audit ledger

---

## 🏗️ Project Structure

```text
Spam Mail Detection/
│
├── dataset/
│   ├── generate_dataset.py     # 3,000-sample multi-channel dataset generator
│   └── spam.csv                # Labeled Email and SMS spam/ham dataset
│
├── model/
│   ├── spam_model.pkl          # Trained VotingClassifier (MultinomialNB + LogisticRegression)
│   ├── vectorizer.pkl          # Fitted TF-IDF Vectorizer
│   ├── risk_model.pkl          # Trained Risk Classifier
│   └── metrics.pkl             # Model performance metrics (100% Accuracy)
│
├── src/
│   ├── __init__.py
│   ├── preprocessing.py        # Text cleaning, stop-words, and Porter stemming
│   ├── url_analyzer.py         # URL extraction & structural lexical analysis
│   ├── phone_analyzer.py       # Phone extraction, country origin, & callback trap detector
│   ├── risk_analyzer.py        # Multi-factor composite risk calculator
│   ├── train.py                # Model training and artifact serialization
│   └── predict.py              # Unified inference engine (Email & SMS)
│
├── templates/
│   ├── base.html               # Responsive navigation & layout shell
│   ├── index.html              # Email & SMS scanner with 8 1-click test scenarios
│   ├── result.html             # Security Report Card with URLs and Phone Numbers
│   ├── history.html            # Searchable audit history & CSV export
│   ├── dashboard.html          # Executive threat intelligence dashboard
│   ├── login.html              # User authentication login
│   └── register.html           # User registration
│
├── static/
│   ├── css/
│   │   └── style.css           # Glassmorphism cyber styles & status glows
│   └── js/
│       └── script.js           # Client-side scripts
│
├── database/
│   ├── __init__.py
│   └── schema.sql              # MySQL DDL schema (users, emails, url_analysis, phone_analysis)
│
├── app.py                      # Flask web application & REST API
├── db.py                       # Database connection layer (MySQL + SQLite fallback)
├── test_app.py                 # Automated unit and integration test suite (8 tests)
├── requirements.txt            # Python dependencies
├── .env                        # Database and environment configuration
├── .gitignore
└── README.md
```

---

## 🚀 Quick Start Guide

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Test Suite (8 Tests)
```bash
python test_app.py
```

### 3. Start the Web Server
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🧪 1-Click Test Scenarios Available in Web UI

### 📱 SMS / Phone Mode Presets:
1. 🔴 **Electricity Power Cut Threat**: "Dear consumer, your electricity power will be disconnected tonight. Call officer at +91-8877665544." $\rightarrow$ **SPAM (96.8%)** &bull; Risk: Utility Disconnection Scam / Vishing &bull; Recommendation: *DO NOT CALL*.
2. 🔴 **Bank YONO / KYC Block**: "Dear SBI user, your YONO account has been blocked due to pending PAN. Update at link or call +91-9876543210." $\rightarrow$ **SPAM (95.4%)** &bull; Risk: Smishing &bull; Recommendation: *DO NOT CLICK OR CALL*.
3. 🔴 **WhatsApp Task Scam**: "Earn Rs. 3000 to Rs. 8000 daily liking YouTube videos. WhatsApp +1 (555) 349-2011." $\rightarrow$ **SPAM (93.1%)** &bull; Risk: Task / Advance Scam &bull; Recommendation: *DO NOT CONTACT ON WHATSAPP*.
4. 🟢 **Legitimate Bank OTP SMS**: "Your OTP for transaction of Rs. 1,499.00 at Amazon Pay is 482910. Valid for 10 mins. - HDFC Bank (VK-HDFCBK)" $\rightarrow$ **HAM (Spam: 2.1%)** &bull; Risk: Very Low.

### 📧 Email Mode Presets:
1. 🟢 **Legitimate Work Ham**: Q3 Sprint Review Meeting $\rightarrow$ **HAM** &bull; Very Low Risk.
2. 🔴 **Phishing & Login**: Account suspension warning with login URL $\rightarrow$ **SPAM** &bull; Credential Theft.
3. 🔴 **Invoice Malware**: Overdue invoice linking to `invoice.exe` $\rightarrow$ **SPAM** &bull; Malware Alert.
4. 🔴 **Lottery Scam**: Lottery winner asking for upfront processing fee $\rightarrow$ **SPAM** &bull; Financial Scam.

---

## 👨‍💻 Author

### Soham Das
**B.Tech — Electronics and Communication Engineering**
