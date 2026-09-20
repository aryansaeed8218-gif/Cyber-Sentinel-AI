import os
import json
import time
from urllib.parse import urlparse

import streamlit as st

from threat_sources import (
    analyze_local,
    scan_virustotal,
    check_abuseipdb,
    scan_urlscan,
    combine_assessment,
    provider_status,
)
from ai_analysis import gemini_analysis


st.set_page_config(
    page_title="Cyber Sentinel",
    page_icon="🛡️",
    layout="wide",
)


def secret(name: str) -> str:
    """Read a secret from Streamlit Secrets, then environment variables."""
    try:
        value = st.secrets.get(name)
        if value:
            return str(value).strip()
    except Exception:
        pass
    return os.getenv(name, "").strip()


def valid_url(value: str):
    try:
        parsed = urlparse(value.strip())
        if parsed.scheme not in ("http", "https"):
            return False, "URL must start with http:// or https://"
        if not parsed.hostname:
            return False, "URL has no hostname."
        return True, ""
    except Exception as exc:
        return False, f"Invalid URL: {exc}"


def show_json(title, data):
    with st.expander(title, expanded=False):
        st.json(json.loads(json.dumps(data, default=str)))


if "result" not in st.session_state:
    st.session_state.result = None


with st.sidebar:
    st.title("🛡️ Cyber Sentinel")
    page = st.radio(
        "Navigation",
        ["Scanner", "Scan History", "About", "Settings"],
    )

    keys = {
        "VirusTotal": secret("VIRUSTOTAL_API_KEY"),
        "AbuseIPDB": secret("ABUSEIPDB_API_KEY"),
        "URLScan": secret("URLSCAN_API_KEY"),
        "Gemini": secret("GEMINI_API_KEY") or secret("GOOGLE_API_KEY"),
    }

    st.caption("Evidence-driven threat intelligence")
    with st.expander("Provider status"):
        for name, configured in provider_status(**keys).items():
            st.write(("🟢 " if configured else "⚪ ") + name)


if page == "About":
    st.title("About")
    st.write(
        "Cyber Sentinel checks a URL using local analysis and optional "
        "external threat-intelligence providers."
    )
    st.info(
        "Unknown does not mean safe. It means there was not enough evidence "
        "to produce a provider-backed assessment."
    )
    st.stop()


if page == "Settings":
    st.title("Settings")
    st.subheader("API configuration")

    st.write("Required secret names:")
    st.code(
        "VIRUSTOTAL_API_KEY\n"
        "ABUSEIPDB_API_KEY\n"
        "URLSCAN_API_KEY\n"
        "GEMINI_API_KEY"
    )

    for name, configured in provider_status(**keys).items():
        if configured:
            st.success(f"{name}: configured")
        else:
            st.warning(f"{name}: not configured")

    st.error(
        "Do not put API keys in the URL, HTML, screenshots, source code, "
        "GitHub, or client-side JavaScript. If a real key was exposed, rotate it."
    )
    st.stop()


if page == "Scan History":
    st.title("Scan History")
    st.info("History is kept only for this running Streamlit session.")
    st.stop()


st.title("Threat Assessment")

url = st.text_input(
    "Indicator",
    placeholder="https://example.com",
)

if st.button("🔎 Scan", type="primary"):
    ok, error = valid_url(url)
    if not ok:
        st.error(error)
        st.stop()

    url = url.strip()

    with st.status("Running security checks...", expanded=True) as status:
        local = analyze_local(url)
        st.write("✓ Local analysis")

        vt = scan_virustotal(url, keys["VirusTotal"])
        st.write(
            "✓ VirusTotal"
            if vt["configured"]
            else "⚪ VirusTotal: API key not configured"
        )

        abuse = None
        ip = local.get("resolved_ip")
        if ip:
            abuse = check_abuseipdb(ip, keys["AbuseIPDB"])
            st.write(
                "✓ AbuseIPDB"
                if abuse["configured"]
                else "⚪ AbuseIPDB: API key not configured"
            )
        else:
            abuse = {
                "provider": "AbuseIPDB",
                "configured": bool(keys["AbuseIPDB"]),
                "status": "No public IP resolved",
                "data": None,
                "error": None,
                "signals": [],
            }

        urlscan = scan_urlscan(url, keys["URLScan"])
        st.write(
            "✓ URLScan"
            if urlscan["configured"]
            else "⚪ URLScan: API key not configured"
        )

        assessment = combine_assessment(
            local,
            vt,
            abuse,
            urlscan,
        )

        ai = gemini_analysis(
            url=url,
            local=local,
            virustotal=vt,
            abuseipdb=abuse,
            urlscan=urlscan,
            api_key=keys["Gemini"],
        )

        status.update(label="Scan finished", state="complete", expanded=False)

    st.session_state.result = {
        "url": url,
        "local": local,
        "virustotal": vt,
        "abuseipdb": abuse,
        "urlscan": urlscan,
        "assessment": assessment,
        "ai": ai,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }


result = st.session_state.result

if not result:
    st.info("Enter a URL and click Scan.")
    st.stop()

assessment = result["assessment"]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Type", "URL")
c2.metric("Threat Score", assessment["score_label"])
c3.metric("Score", f'{assessment["score"]}/100')
c4.metric("Evidence Coverage", assessment["coverage"])

st.subheader("Threat Intelligence Sources")

items = [
    result["virustotal"],
    result["abuseipdb"],
    result["urlscan"],
]

cols = st.columns(3)
for col, item in zip(cols, items):
    with col:
        if item.get("configured"):
            st.success(item["provider"])
        else:
            st.warning(item["provider"])
        st.write(item.get("status", "No status"))

st.subheader("Local Analysis")
show_json("Local evidence", result["local"])

st.subheader("Security Signals")
signals = []
for source in (
    result["local"],
    result["virustotal"],
    result["abuseipdb"],
    result["urlscan"],
):
    if source:
        signals.extend(source.get("signals", []))

if signals:
    for signal in signals:
        st.write("• " + signal)
else:
    st.info("No additional security signals were returned.")

st.subheader("AI Security Analysis")
if result["ai"].get("text"):
    st.write(result["ai"]["text"])
elif result["ai"].get("error"):
    st.warning(result["ai"]["error"])
else:
    st.info("Gemini is not configured.")

show_json("VirusTotal technical evidence", result["virustotal"])
show_json("AbuseIPDB technical evidence", result["abuseipdb"])
show_json("URLScan technical evidence", result["urlscan"])

if assessment["score_label"] == "Unknown":
    st.warning(
        "Assessment is Unknown because external evidence is missing. "
        "This is not a statement that the URL is safe."
    )
