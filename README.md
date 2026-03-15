# PhishGuard 🛡️

**PhishGuard** is a comprehensive, multi-vector Threat Intelligence Platform and URL Analysis framework designed to detect phishing and malicious websites. Developed as an academic project, it incorporates various intelligence modules and an embedded Machine Learning engine to classify risk.

![PhishGuard Overview](https://img.shields.io/badge/Status-Active-success)
![Python](https://img.shields.io/badge/Language-Python-blue)
![Machine Learning](https://img.shields.io/badge/ML-Scikit_Learn-orange)

## Features & Threat Intelligence Modules

1. **Dashboard UI**: Professional, "Glassmorphism" interface with animated threat gauges, a dark theme, and asynchronous results processing.
2. **Machine Learning Predictor**: Uses a trained **Random Forest Classifier** (`scikit-learn`) to evaluate domain characteristics against known phishing patterns.
3. **Internal Heuristics Analyzer**: 
   - Flags raw IP domains.
   - Detects masking techniques (`@` symbol).
   - Identifies injection payloads (`&&`, `="`).
   - Checks for credential-harvesting keywords (`admin`, `passwd`).
   - Identifies uncommon TLDs (`.cin`, etc).
4. **WHOIS Domain Validation**: Integrates live Domain Age calculation, spotting brand-new "burner" domains (often used in phishing), and calculates Registrar and Expiry data.
5. **SSL Cryptographic Check**: Extracts underlying SSL Issuers and dynamically calculates Certificate Expiry time down to the day.
6. **Live Payload Scraping**: Analyzes the active HTML payloads using `BeautifulSoup4` to detect hidden credential harvesting forms (`<input type="password">`).
7. **Global API Threat Lookups**: Actively interfaces with the **URLHaus (Abuse.ch)** Threat Database API to cross-reference targets against real-time global malware tracking.

## Architecture

* **Frontend**: Vanilla JS (ES6+), CSS3 Variables & Flexbox Grids, HTML5.
* **Backend**: Python 3, Flask server architecture.
* **Libraries**: `requests`, `python-whois`, `beautifulsoup4`, `scikit-learn`, `joblib`, `numpy`.

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/spideyshan/Phishing_Detection.git
   cd Phishing_Detection
   ```

2. **Set up a Virtual Environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Requirements:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize Machine Learning Model:**
   _(Run the training script to generate the `.pkl` engine file before launching the app)_
   ```bash
   python train_model.py
   ```

5. **Run the Application:**
   ```bash
   python app.py
   ```

6. **Access Dashboard:** Open a web browser to `http://127.0.0.1:5001`.

## Legal & Disclaimer

* **Academic Use Only:** This tool is designed for educational research and threat analysis.
* **No Warranty:** PhishGuard cannot guarantee 100% detection of advanced persistent threats (APTs). Always exercise independent security verification when entering sensitive credentials online.
