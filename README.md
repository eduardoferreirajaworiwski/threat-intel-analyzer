# 🛡️ Threat Intel Analyzer

**Threat Intel Analyzer** is a SecOps and Cybersecurity data analysis tool. It processes raw server logs and applies **real-time network threat intelligence** by correlating origin IP addresses against multiple intelligence feeds (VirusTotal and Shodan). It features a robust Streamlit-based web dashboard designed with a custom Cybersecurity Dark theme.

## ✨ Key Features

- **Double Enrichment Pipeline (`analyzer.py`)**: 
  - **VirusTotal API v3**: Fetches IP reputation and malicious votes.
  - **Shodan API**: Gathers infrastructure footprint (operating system, ISP/organization, open ports).
- **Interactive Security Dashboard (`app.py`)**: 
  - Visually engaging dark theme UI.
  - Interactive metrics cards, Play/Pause execution feedback.
  - Plotly graphs visualizing top targeted ports and action distributions.
- **Smart Column Detection (`column_detector.py`)**:
  - Automatically identifies column semantics (IPs, events, ports, timestamps) even if the uploaded CSV headers are misnamed or localized, using data sampling and validation rules.
- **Automated Reporting (`pdf_generator.py`)**: 
  - Exports an executive summary PDF mimicking the dashboard's design aesthetics, summarizing total threats discovered and top attacker networks.

## 📂 Project Structure

```
threat-intel-analyzer/
├── app.py                  # Streamlit Dashboard & Web Interface
├── analyzer.py             # Threat Intelligence enrichment engine
├── column_detector.py      # Auto-detects schema of arbitrary CSVs
├── pdf_generator.py        # PDF export module using fpdf2
├── generate_logs.py        # Mock data generator (creates server_logs.csv)
├── requirements.txt        # Pinned Python dependencies
├── .env.example            # Template for your API keys
├── testes_app.py           # Unit tests for the application
└── venv/                   # Local Virtual Environment (Recommended)
```

## ⚙️ Setup and Installation

### 1. Requirements
Ensure you are using Python 3 (preferably Python 3.10+). For Debian/Ubuntu environments where global `pip` modifications are restricted, use the provided virtual environment configuration.

### 2. Environment Setup
Clone the repository and jump into it, then create a local virtual environment:

```bash
python3 -m venv venv
```

Activate the virtual environment:
```bash
# On Linux / macOS
source venv/bin/activate
```

Install the dependencies:
```bash
pip install -r requirements.txt
```

### 3. API Keys Configuration
The project securely reads secrets from an `.env` file. You need active keys from Shodan and VirusTotal.
1. Copy the template:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` and fill in your keys:
   ```env
   VT_API_KEY=your_virustotal_api_key_here
   SHODAN_API_KEY=your_shodan_api_key_here
   ```

## 🚀 Usage

### Option 1: Generate Mock Data
If you don't have server logs available, you can generate 50 random records (injected with several known malicious IPs for testing):
```bash
python generate_logs.py
```
*(This produces `server_logs.csv` in the root folder).*

### Option 2: Run the SecOps Dashboard
Boot up the Streamlit application interface:
```bash
streamlit run app.py
```
- Open `http://localhost:8501` in your browser.
- Select your logs locally via the sidebar or upload a `.csv` file. The Smart Column Detection will automatically analyze and map your fields.
- Click **Executar Análise Completa** to initialize the Threat Intel scraping (this respects VirusTotal's Free Tier limits by enforcing a 15-second sleep per IP).
- Once processed, utilize the dashboard filters and download your customized **Executive PDF Report**.

## 🛑 Security Constraints
- **Do not commit your `.env`**: Always ensure `.env` and `threat_intel_report.csv` remain ignored in version control tools. 
- **Rate Limits**: The default free instance of VirusTotal enforces a maximum of 4 calls per minute. The analyzer accommodates this rate automatically.
