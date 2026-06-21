# 🛡️ Phishing Awareness Analysis Toolkit

A cybersecurity project that analyzes suspicious emails using phishing red flags, suspicious sender/domain patterns, urgency triggers, dangerous attachment indicators, credential theft signals, and executive fraud techniques.

This project helps classify emails into:
- **Safe**
- **Suspicious**
- **Malicious**

It includes:
- **Python-based phishing analysis engine**
- **Interactive web dashboard UI**
- **Sample phishing email scenarios**
- **Automated triage report generation**

---

## 📌 Project Overview

Phishing is one of the most common cyber attacks used to steal credentials, spread malware, and trick users into taking unsafe actions.  
This project was built to demonstrate how suspicious emails can be analyzed using common phishing indicators and red-flag based detection logic.

The toolkit scans an email's:

- **Sender**
- **Subject**
- **Body content**

and checks for multiple phishing indicators such as:

- Sender/domain mismatch
- Urgency or fear-based language
- Credential harvesting attempts
- Dangerous attachments
- Fake forwarded messages
- MFA fatigue prompts
- Security callback scams (TOAD)
- QR-code phishing prompts
- Executive / CEO fraud patterns

---

## 🚀 Features

- Detects **11 phishing red flag categories**
- Scans email content for suspicious keywords and patterns
- Detects suspicious sender/domain naming patterns
- Classifies emails as:
  - **Safe**
  - **Suspicious**
  - **Malicious**
- Generates an easy-to-read **triage report**
- Includes **sample phishing emails** for testing
- Includes a **modern phishing awareness web dashboard**
- Good for **cybersecurity academic project / portfolio showcase**

---

## 🧠 Red Flags Detected

The phishing engine checks for the following categories:

1. **RF1 - Sender/Domain Mismatch**
2. **RF2 - Fake Forwarded Chains**
3. **RF3 - Urgency / Fear Trigger**
4. **RF4 - Dangerous Attachments**
5. **RF5 - Urgent Bypass Requests**
6. **RF6 - Request for Sensitive Information**
7. **RF7 - Sign-in / Security Alerts**
8. **RF8 - MFA Fatigue Attacks**
9. **RF9 - Security Callback Scam (TOAD)**
10. **RF10 - QR Code Prompts**
11. **RF11 - Deepfake / Executive Fraud**

---

## 🛠️ Tech Stack

### Backend / Logic
- **Python 3**

### Frontend
- **HTML**
- **CSS**
- **JavaScript**

---

## 📂 Project Structure

```bash
phishing-awareness-analysis-toolkit/
│
├── app.py / phishing_analysis.py      # Python phishing analysis engine
├── index.html                         # Web dashboard / phishing analyzer UI
├── README.md                          # Project documentation
└── sample emails / project files
