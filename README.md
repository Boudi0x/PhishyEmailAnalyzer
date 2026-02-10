# 🛡️ PhishyEmailAnalyzer

PhishyEmailAnalyzer is a Python-based desktop application designed to analyze suspicious emails and identify phishing indicators.

The tool helps Blue Team members and SOC analysts inspect email headers, authentication results, URLs, and attachments in a clear and structured way.

---

## 📸 Screenshots

![Splash Screen](splash.png)

![Input Page](input.png)

![Results Page](results.png)


---

## 🔍 Features

- Email header extraction  
  (From, To, Subject, Date, Reply-To, Return-Path)

- Email authentication analysis  
  - SPF
  - DKIM
  - DMARC

- URL extraction
  - Supports encoded URLs
  - Detects nested / redirected links

- Attachment analysis
  - Extracts attachment names
  - Calculates SHA-256 hashes

- Domain & IP investigation support

- Integrated with:
  - VirusTotal
  - AbuseIPDB
  - Browserling
  - CyberChef

---

## 🛠️ Tech Stack

- Python
- CustomTkinter (GUI)
- Regular Expressions (Regex)
- Base64 decoding
- SHA-256 hashing

---

## ▶️ How to Run

1. Make sure Python is installed on your system  
2. Install the required dependency: pip install -r requirements.txt
3. Run the application: python main.py



