import streamlit as st
from datetime import datetime, timezone
from pathlib import Path
from threat_sources import analyze_indicator, detect_indicator_type, validate_indicator, get_api_availability

st.set_page_config(page_title="Cyber Sentinel AI", page_icon="🛡️", layout="wide")
st.markdown("""<style>
.stApp{background:#081421;color:#F5F7FA}.stSidebar{background:#102235}
.block-container{max-width:1400px;padding-top:2rem}.hero{background:#102235;border:1px solid #2F81F7;border-radius:18px;padding:25px;margin-bottom:20px}
.card{background:#142A3D;border:1px solid #29445c;border-radius:14px;padding:18px;min-height:120px}
.muted{color:#AAB7C4}.pill{display:inline-block;padding:6px 12px;border-radius:99px;background:#2F81F7;color:white;font-weight:700}
</style>""", unsafe_allow_html=True)

if "history" not in st.session_state: st.session_state.history=[]
if "result" not in st.session_state: st.session_state.result=None

def card(title,value,sub=""):
    st.markdown(f'<div class="card"><div class="muted">{title}</div><h2>{value}</h2><div class="muted">{sub}</div></div>',unsafe_allow_html=True)

def show_result(r):
    st.subheader("Threat Assessment")
    a,b,c,d=st.columns(4)
    with a: card("Indicator",r["indicator"])
    with b: card("Type",r["indicator_type"])
    with c: card("Threat Score",r["score"] if r["score"] is not None else "Unknown",r["label"])
    with d: card("Evidence Coverage",r["coverage"],"Provider availability")
    if r["score"] is not None: st.progress(r["score"]/100)
    if r["conflicts"]: st.warning("Conflicting evidence detected: "+"; ".join(r["conflicts"]))
    st.subheader("Threat Intelligence Sources")
    cols=st.columns(4)
    for col,name,key in zip(cols,["VirusTotal","AbuseIPDB","URLScan","Local Analysis"],["virustotal","abuseipdb","urlscan","local"]):
        with col:
            data=r.get(key)
            card(name,"Evidence available" if data else "Unavailable / No result")
    st.subheader("Security Signals")
    if r["signals"]: st.dataframe(r["signals"],use_container_width=True,hide_index=True)
    else: st.info("No additional security signals were returned.")
    st.subheader("AI Security Analysis")
    st.markdown(r.get("ai_analysis") or "Gemini is not configured or did not return an analysis.")
    links=r.get("links",{})
    if links:
        st.subheader("Official External Results")
        for name,url in links.items(): st.markdown(f"- [{name}]({url})")
    with st.expander("Technical Evidence JSON"): st.json(r["evidence"])
    if r["errors"]:
        with st.expander("Provider / Processing Notes"):
            for e in r["errors"]: st.warning(e)

page=st.sidebar.radio("Navigation",["Scanner","Scan History","About","Settings"])
st.sidebar.caption("Evidence-driven threat intelligence")

if page=="Scanner":
    st.markdown('<div class="hero"><h1>🛡️ Cyber Sentinel AI</h1><p>Intelligent Threat Detection. Safer Digital Decisions.</p></div>',unsafe_allow_html=True)
    kind=st.selectbox("Indicator Type",["IP Address","URL","Domain","Custom Indicator"])
    placeholders={"IP Address":"8.8.8.8","URL":"https://example.com/path","Domain":"example.com","Custom Indicator":"IP, domain, or HTTP/HTTPS URL"}
    value=st.text_input("Indicator",placeholder=placeholders[kind])
    if kind=="URL":
        st.warning("URLScan submission shares the URL with URLScan. Never submit credentials, tokens, private URLs, or sensitive data.")
    if st.button("🔍 Scan Indicator",type="primary",use_container_width=True):
        detected=detect_indicator_type(value) if kind=="Custom Indicator" else kind
        normalized,error=validate_indicator(value,detected)
        if error: st.error(error)
        else:
            with st.status("Running security analysis...",expanded=True) as status:
                st.write("Validating indicator")
                st.write("Collecting available threat intelligence")
                r=analyze_indicator(normalized,detected)
                st.write("Normalizing evidence and calculating deterministic score")
                st.write("Generating evidence-constrained AI interpretation")
                status.update(label="Scan completed",state="complete",expanded=False)
            r["scanned_at"]=datetime.now(timezone.utc).isoformat()
            st.session_state.result=r
            st.session_state.history.insert(0,{"time":r["scanned_at"],"indicator":r["indicator"],"type":r["indicator_type"],"score":r["score"],"status":r["label"]})
    if st.session_state.result:
        st.divider(); show_result(st.session_state.result)

elif page=="Scan History":
    st.markdown('<div class="hero"><h1>🛡️ Scan History</h1><p>Session-only results.</p></div>',unsafe_allow_html=True)
    if st.session_state.history: st.dataframe(st.session_state.history,use_container_width=True,hide_index=True)
    else: st.info("No scans in this session.")
    if st.button("Clear History"): st.session_state.history=[]; st.session_state.result=None; st.rerun()

elif page=="About":
    st.markdown('<div class="hero"><h1>🛡️ About Cyber Sentinel AI</h1><p>Intelligent Threat Detection. Safer Digital Decisions.</p></div>',unsafe_allow_html=True)
    st.markdown("Cyber Sentinel AI combines local validation with optional VirusTotal, AbuseIPDB, URLScan and Gemini evidence interpretation.")
    st.info("Threat intelligence may be incomplete or delayed. This tool is an analysis aid, not a guarantee of safety.")
    st.warning("External providers may receive submitted indicators. Do not submit credentials, tokens, private URLs or sensitive information.")

else:
    st.markdown('<div class="hero"><h1>⚙️ Settings</h1><p>Integration status. Secret values are never displayed.</p></div>',unsafe_allow_html=True)
    av=get_api_availability()
    cols=st.columns(4)
    for col,name,key in zip(cols,["Gemini","VirusTotal","AbuseIPDB","URLScan"],["gemini","virustotal","abuseipdb","urlscan"]):
        with col: card(name,"Connected" if av[key] else "Not configured")
