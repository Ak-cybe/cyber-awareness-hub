# 🛡️ Cyber Awareness Hub

> **Protect Your Digital Life** — An interactive cybersecurity awareness platform that teaches users to identify phishing attacks, build strong passwords, and practice daily security hygiene.

![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)

---

## ✨ Features

### 🔍 Phishing Anatomy Simulator
- **5 real-world phishing scenarios** — PayPal spoofs, invoice fraud, HR payroll scams, fake IT updates, and MFA fatigue attacks
- Click on suspicious elements to learn **why** they're dangerous
- Score tracking with localStorage persistence

### 🔐 Password Strength Lab
- Real-time password strength meter with visual feedback
- Rule-based validation (length, symbols, case mix)
- Color-coded strength bar with glow effects

### ✅ Daily Security Hygiene Checklist
- Track 2FA/MFA, software updates, backups, and screen lock habits
- Persistent checkbox state via localStorage

### 🔬 Phishing URL & Email Analyzer
- **URL Analysis** — Detects suspicious TLDs, typosquatting, IP-based URLs, data URIs, cousin domains, and more (14+ detection patterns)
- **Email Forensics** — Full .eml file upload or raw paste support with:
  - Header analysis (SPF, DKIM, DMARC)
  - URL extraction and risk scoring
  - Attachment analysis
  - Transmission path tracing
  - X-header inspection
- Risk scoring with diminishing returns and cross-category convergence

### ⚙️ API Configuration
- Connect external threat intelligence APIs:
  - **VirusTotal** — Malware and URL scanning
  - **Google Safe Browsing** — Real-time URL threat data
  - **PhishTank** — Community-driven phishing database
- API keys stored securely in browser localStorage

### 🎓 External Training Integration
- Direct link to CDSE (Center for Development of Security Excellence) cybersecurity course

---

## 🚀 Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/Ak-cybe/cyber-awareness-hub.git
   cd cyber-awareness-hub
   ```

2. **Open in browser**
   ```bash
   # Simply open index.html in your browser
   # Or use a local server:
   npx serve .
   ```

No build step required — this is a pure HTML/CSS/JS application.

---

## 📁 Project Structure

```
cyber-awareness-hub/
├── index.html      # Main application (single-page dashboard)
├── styles.css      # Complete styling with glassmorphism design
├── script.js       # All interactive logic and analysis engines
├── mvprule.md      # MVP research plan and roadmap
├── LICENSE         # MIT License
└── README.md       # This file
```

---

## 🎨 Design

- **Glassmorphism UI** with frosted glass cards
- **Dark theme** with cyan/green/red accent system
- **Responsive bento grid layout** (adapts to mobile)
- **Micro-animations** — hover effects, glow transitions, fade-ins
- **Inter font** via Google Fonts

---

## 🔧 API Setup (Optional)

The Phishing Analyzer works offline with pattern-based detection. For enhanced analysis, configure API keys:

| API | Purpose | Get Key |
|-----|---------|---------|
| VirusTotal | Malware/URL scanning | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |
| Google Safe Browsing | Real-time URL threats | [console.cloud.google.com](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com) |
| PhishTank | Phishing database | [phishtank.org](https://phishtank.org/api_info.php) |

---

## 🤝 Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is for **educational purposes only**. It uses client-side pattern matching and heuristics — it is not a replacement for enterprise-grade security solutions. Never rely solely on this tool for real-world phishing detection.

---

<p align="center">
  <strong>© 2025 CyberGuard Architect</strong><br>
  Built with ❤️ for cybersecurity awareness
</p>
