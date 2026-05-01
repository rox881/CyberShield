# CyberShield 🛡

**AI-powered real-time phishing detection** for emails, URLs, and attachments.

Built for the AI/ML & Cybersecurity Hackathon.

## Project Summary

CyberShield is a comprehensive, AI-driven cybersecurity solution designed to detect and prevent phishing attacks in real-time. Operating fully locally to guarantee data privacy, it uses advanced large language models (Llama 3.1 8B and Phi-3 Mini) to run multi-signal heuristic analysis on emails, URLs, and file attachments. Integrated via a Chrome Extension and powered by a FastAPI backend, CyberShield immediately flags threats like credential harvesting, brand impersonation, urgency-based social engineering, and suspicious domains while providing detailed AI-generated explanations for every detection.

### Key Updates (v1.1)
- Switched primary model to **Llama 3.1 8B** → significantly better reasoning and precision
- Increased detection sensitivity (lower thresholds)
- Improved LLM prompts for detailed, consistent explanations
- Better false-negative reduction on phishing emails and links

---

## Features

| Feature                        | Status |
|--------------------------------|--------|
| Real-time Gmail overlay        | ✅     |
| Multi-signal heuristic analysis| ✅     |
| URL threat detection           | ✅     |
| AI-generated content detection | ✅     |
| Detailed explanations          | ✅     |
| Chrome Extension               | ✅     |
| Local LLM (no data sent out)   | ✅     |
| Attachment static analysis     | ✅     |
| Sandbox dynamic analysis       | 🔜 V2  |

---

## Quick Start

### 1. Install Ollama + Models

```bash
ollama pull llama3.1:8b
ollama pull phi3:mini
```

### 2. Start the Backend

```bash
cd backend
pip install -r requirements.txt

# Copy environment file
cp ../.env.example ../.env

# Recommended settings for higher sensitivity:
# THRESHOLD_SAFE=25
# THRESHOLD_SUSPICIOUS=55
# PRIMARY_MODEL=llama3.1:8b-instruct

mkdir -p ../data
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Load the Chrome Extension

1. Go to `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder

### 4. Open the Dashboard

Open `frontend/index.html` in your browser (or click "Open Dashboard" in the extension popup).

---

## Recommended Configuration (for higher phishing detection)

In `.env`:

```env
PRIMARY_MODEL=llama3.1:8b
FAST_MODEL=phi3:mini

# More sensitive detection
THRESHOLD_SAFE=25
THRESHOLD_SUSPICIOUS=55
```

## Detection Signals

- Urgency language
- Credential harvesting requests
- Brand impersonation
- Suspicious sender & lookalike domains
- IP addresses in URLs
- URL shorteners, encoding, suspicious paths
- Text quality anomalies

## Tech Stack

- **Backend:** FastAPI + Python 3.11
- **AI:** Ollama (Llama 3.1 8B Instruct + Phi-3 Mini) — fully local
- **Database:** SQLite
- **Frontend:** Vanilla HTML/CSS/JS + Chart.js
- **Extension:** Chrome Manifest V3

---
Made with ❤️ for better phishing protection.