# RedireX 🚀

<p align="center">
  <b>An Advanced, Asynchronous Open Redirect Scanner</b>
</p>

RedireX is a powerful tool designed to help identify Open Redirect vulnerabilities quickly and efficiently. It combines fast header-based scanning with headless browser (JavaScript) execution to catch elusive client-side redirects. 

## ✨ Features
* **Asynchronous Engine:** Highly concurrent HTTP probing and vulnerability scanning.
* **Smart Reconnaissance:** Integrates with `crt.sh`, `CertSpotter`, `Subfinder`, and `Amass` for subdomain enumeration, and `gau` for endpoint gathering.
* **Deep JS Scanning:** Uses Playwright to detect DOM-based and JavaScript-triggered redirects.
* **Parameter Fuzzing:** Automatically injects the most common redirect parameters into static endpoints.
* **AI Reporting:** Integrates with Gemini (1.5-Flash) to automatically generate vulnerability impact and remediation reports.

## ⚙️ Installation

**1. Clone the repository:**
```bash
git clone [https://github.com/kareemelmongy/RedireX.git](https://github.com/kareemelmongy/RedireX.git)
cd RedireX
```
2. Install Python dependencies:
```bash
pip install -r requirements.txt
```
3. Install Playwright browsers (for JS scanning):
```bash
playwright install chromium
```
4. Install External Dependencies:
For full reconnaissance capabilities, ensure the following Go tools are installed and in your system's PATH:
gau => https://github.com/lc/gau

subfinder => https://github.com/projectdiscovery/subfinder

amass => https://github.com/owasp-amass/amass


🚀 Usage
Full Reconnaissance & Scan Mode:
```bash
python3 RedireX.py -d target.com -P payloads.txt --js-scan -oJ results.json
```
Single Target/Endpoint File Mode:
```bash
python3 RedireX.py -e endpoints.txt -P [http://evil.com](http://evil.com) --fuzz 10
```
AI Report Generation:
```bash
python3 RedireX.py -d target.com -P payloads.txt --apikey YOUR_GEMINI_KEY --reportoutput report.txt
```

⚠️ Disclaimer
This tool is intended for educational purposes and authorized penetration testing only. The developer is not responsible for any misuse or damage caused by this tool. Always ensure you have explicit permission before scanning any target.
