import streamlit as st
import requests
import pandas as pd
import json

# Set page config
st.set_page_config(page_title="RiskScope - IP Threat Checker with Ollama AI", layout="wide")

# API keys
VIRUSTOTAL_API_KEY = "VT_API"
ABUSEIPDB_API_KEY = "ABIPDB_API"

# === Ollama config ===
OLLAMA_API_URL = "http://localhost:11434/api/chat"
OLLAMA_MODEL_NAME = "llama3.2" 


# -------------------- VirusTotal --------------------
def get_virustotal_data(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        res = response.json()
        data = res["data"]["attributes"]
        return {
            "Malicious": data["last_analysis_stats"]["malicious"],
            "Suspicious": data["last_analysis_stats"]["suspicious"],
            "Undetected": data["last_analysis_stats"]["undetected"],
            "Harmless": data["last_analysis_stats"]["harmless"],
            "Country": data.get("country", "N/A"),
            "ASN": data.get("asn", "N/A"),
            "Tags": data.get("tags", []),
        }
    return {"Error": f"VirusTotal error {response.status_code}"}


# -------------------- AbuseIPDB --------------------
def get_abuseipdb_data(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        res = response.json()["data"]
        return {
            "Country Code": res.get("countryCode", "N/A"),
            "ISP": res.get("isp", "N/A"),
            "Abuse Confidence Score": res.get("abuseConfidenceScore", 0),
            "Total Reports": res.get("totalReports", 0),
            "Last Reported At": res.get("lastReportedAt", "N/A"),
        }
    return {"Error": f"AbuseIPDB error {response.status_code}"}


# -------------------- Who.is --------------------
def get_whois_data(ip):
    try:
        response = requests.get(f"https://rdap.arin.net/registry/ip/{ip}")
        if response.status_code == 200:
            data = response.json()
            name = data.get("name", "N/A")
            cidr = data.get("cidr0", {}).get("cidr", "N/A")
            ip_range = data.get("startAddress", "N/A") + " - " + data.get("endAddress", "N/A")
            return {
                "Organization": name,
                "CIDR": cidr,
                "Range": ip_range,
            }
    except Exception as e:
        return {"Error": f"Whois error: {e}"}
    return {"Error": f"Whois error {response.status_code}"}


def generate_ai_summary(ip, vt_data, abuse_data, whois_data):
    prompt = f"""
You are a cybersecurity analyst. Given the threat intelligence for IP address {ip}, generate a concise professional summary of its potential risk level.

VirusTotal:
Malicious: {vt_data.get("Malicious")}
Suspicious: {vt_data.get("Suspicious")}
Undetected: {vt_data.get("Undetected")}
Harmless: {vt_data.get("Harmless")}
Country: {vt_data.get("Country")}
ASN: {vt_data.get("ASN")}
Tags: {', '.join(vt_data.get("Tags", []))}

AbuseIPDB:
Country Code: {abuse_data.get("Country Code")}
ISP: {abuse_data.get("ISP")}
Abuse Confidence Score: {abuse_data.get("Abuse Confidence Score")}
Total Reports: {abuse_data.get("Total Reports")}
Last Reported At: {abuse_data.get("Last Reported At")}

Whois:
Organization: {whois_data.get("Organization")}
CIDR: {whois_data.get("CIDR")}
Range: {whois_data.get("Range")}

Summarize the threat context and assign a final risk level (Low, Medium, High). Start with the summarized threat level displayed in format in bold- Risk Assessment:<Risk Level>\n. Give a maximum 30 word summary with no points on the maliciousness potential of the IP(Take into account recent reports as well)
"""

    try:
        response = requests.post(
            OLLAMA_API_URL,
            headers={"Content-Type": "application/json"},
            json={
                "model": OLLAMA_MODEL_NAME,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "stream": False,
            },
            timeout=30,
        )
        if response.status_code == 200:
            return response.json()["message"]["content"].strip()
        else:
            return f"Ollama AI error {response.status_code}: {response.text}"
    except Exception as e:
        return f"Ollama connection error: {e}"


# -------------------- Streamlit UI --------------------
st.title("🛡️ RiskScope - IP Threat Intelligence Checker")
st.write("Enter one or more IP addresses (comma-separated) to assess potential threats using VirusTotal, AbuseIPDB, Whois, and AI-powered risk summarization using Ollama (LLaMA 3).")

ip_input = st.text_area("Enter IP Addresses (comma separated)", height=150)
ips = [ip.strip() for ip in ip_input.split(",") if ip.strip()]
data = []

if st.button("Check IP"):
    with st.spinner("Gathering threat intel and generating AI summaries..."):
        for ip in ips:
            vt = get_virustotal_data(ip)
            abuse = get_abuseipdb_data(ip)
            whois = get_whois_data(ip)
            ai_summary = generate_ai_summary(ip, vt, abuse, whois)
            data.append({
                "IP Address": ip,
                "VirusTotal": vt,
                "AbuseIPDB": abuse,
                "Who.is": whois,
                "AI Summary": ai_summary,
            })

if data:
    for entry in data:
        st.markdown("**🧠 AI-Powered Risk Summary:**")
        st.info(entry["AI Summary"])
        st.markdown("---")

        st.markdown(f"### 🔍 {entry['IP Address']}")
        col1, col2, col3 = st.columns(3)

        with col1:
            st.subheader("VirusTotal")
            st.json(entry["VirusTotal"])

        with col2:
            st.subheader("AbuseIPDB")
            st.json(entry["AbuseIPDB"])

        with col3:
            st.subheader("Who.is")
            st.json(entry["Who.is"])

