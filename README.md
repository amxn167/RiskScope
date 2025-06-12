# 🤖 RiskScope: AI-Powered IP Threat Intelligence Platform

**RiskScope** is a streamlined, AI-assisted threat intelligence tool designed for SOC analysts, threat hunters, and cybersecurity professionals. It aggregates **IP address** reputation data from multiple open-source threat intel APIs (VirusTotal, AbuseIPDB, Whois, etc.) and generates actionable, concise risk summaries using a locally running LLaMA 3 model via [Ollama](https://ollama.com/). Built with **Streamlit**, the tool offers an intuitive web interface for quick, multi-IP analysis.

---

##  Features

-  Bulk **IP reputation lookup** across trusted platforms:
    - [VirusTotal](https://virustotal.com/)
    - [AbuseIPDB](https://abuseipdb.com/)
    - [Whois (ARIN RDAP)](https://rdap.arin.net/)
-  **AI Risk Summary**: Local LLM (LLaMA 3.2 via Ollama) evaluates and summarizes the threat context and assigns a risk level (Low, Medium, High).
-  **Cross-validation**: Detects conflicts like "clean on VirusTotal but flagged on AbuseIPDB".
-  Insight into **"clean" IPs** that may be abused for malicious purposes (e.g., residential proxies).
-  **Streamlit-based GUI** — no terminal needed.

---

## 📦 Tech Stack

| Component | Stack |
| --- | --- |
| UI Framework | Streamlit |
| LLM Integration | LLaMA 3.2 via Ollama (local) |
| Data Sources | VirusTotal, AbuseIPDB, ARIN Whois |
| Language | Python |

---

##  Installation

1. **Clone the Repository**

```bash
git clone https://github.com/amxn167/riskscope.git
cd riskscope
```

1. **Install Dependencies**

```bash

pip install -r requirements.txt

```

---

##  LLaMA 3 + Ollama Setup (Local AI)

1. **Install Ollama**
    - https://ollama.com/download
2. **Download the Model**

```bash
ollama pull llama3
```

1. **Start the Model**

```bash
ollama run llama3
```

Ensure the server runs at `http://localhost:11434`.

---
## OpenAI Integration(Optional)

1. Install OpenAI

```jsx
pip install openai
```

1. Add at the top of your script:

```python
python
CopyEdit
import openai

# OpenAI API Key
openai.api_key = st.secrets["openai_key"]

```

1. AI Summary Function:

```python
python
CopyEdit
def generate_ai_summary(ip, vt_data, abuse_data, whois_data):
    summary_prompt = <Same as original>
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst generating risk summaries based on threat intel reports."},
                {"role": "user", "content": summary_prompt}
            ],
            temperature=0.4,
            max_tokens=250
        )
        return response.choices[0].message['content'].strip()
    except Exception as e:
        return f"AI summary error: {e}"
```
---
##  Streamlit Web UI

The UI is built with [Streamlit](https://streamlit.io/), offering:

- A textarea for entering **comma-separated IPs**
- Side-by-side view of:
    - VirusTotal results
    - AbuseIPDB reports
    - Whois info
- AI-generated risk summary with classification

Launch it using:

```bash
streamlit run RiskScope.py
```

Or for Noob failed python installations(like myself):

```jsx
python3 -m streamlit run RiskScope.py
```

## Screenshots/Working:
![image.png](https://github.com/amxn167/RiskScope/blob/main/Screenshots/Base.png)
![image.png](https://github.com/amxn167/RiskScope/blob/main/Screenshots/Clean.png)
![image.png](https://github.com/amxn167/RiskScope/blob/main/Screenshots/Malicious.png)
