import base64,ipaddress,re,time
from urllib.parse import urlparse,quote
import requests,streamlit as st
try:
    from google import genai
except Exception: genai=None

TIMEOUT=15
def secret(k):
    try:return str(st.secrets.get(k,"")).strip() or None
    except Exception:return None

def get_api_availability():
    return {k:bool(secret(v)) for k,v in {"gemini":"GEMINI_API_KEY","virustotal":"VIRUSTOTAL_API_KEY","abuseipdb":"ABUSEIPDB_API_KEY","urlscan":"URLSCAN_API_KEY"}.items()}

def detect_indicator_type(x):
    x=x.strip()
    try: ipaddress.ip_address(x); return "IP Address"
    except ValueError: pass
    return "URL" if urlparse(x).scheme.lower() in ("http","https") else "Domain"

def domain_ok(x):
    x=x.rstrip(".")
    if not x or len(x)>253 or " " in x:return False
    try:x=x.encode("idna").decode()
    except UnicodeError:return False
    if len(x.split("."))<2:return False
    return all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",p) for p in x.split("."))

def validate_indicator(x,t):
    x=x.strip()
    if not x:return None,"Indicator cannot be empty."
    if t=="IP Address":
        try:return str(ipaddress.ip_address(x)),None
        except ValueError:return None,"Invalid IPv4 or IPv6 address."
    if t=="Domain":
        x=x.rstrip(".").lower()
        return (x,None) if domain_ok(x) else (None,"Invalid domain syntax.")
    if t=="URL":
        if len(x)>8192:return None,"URL is too long."
        p=urlparse(x)
        if p.scheme.lower() not in ("http","https") or not p.hostname:return None,"Only valid HTTP/HTTPS URLs are supported."
        if p.username or p.password:return None,"URLs containing embedded credentials are not accepted."
        try:_=p.port
        except ValueError:return None,"Invalid URL port."
        try:ipaddress.ip_address(p.hostname); ok=True
        except ValueError:ok=domain_ok(p.hostname)
        return (x,None) if ok else (None,"Invalid URL hostname.")
    return None,"Unsupported indicator type."

def req(method,url,**kw):
    kw.setdefault("timeout",TIMEOUT)
    try:r=requests.request(method,url,**kw)
    except requests.Timeout:return None,"Request timed out."
    except requests.RequestException as e:return None,f"Network error: {e}"
    if r.status_code==404:return None,"Result not found."
    if r.status_code==429:return None,"Rate limit reached."
    if r.status_code in (401,403):return None,"Provider authentication/permission error."
    if r.status_code>=400:return None,f"Provider HTTP {r.status_code}."
    try:return r.json(),None
    except ValueError:return None,"Invalid JSON response."

def vt(ind,t):
    k=secret("VIRUSTOTAL_API_KEY")
    if not k:return None,"Not configured."
    if t=="IP Address": path=f"ip_addresses/{quote(ind,safe='')}"
    elif t=="Domain": path=f"domains/{quote(ind,safe='')}"
    else:
        uid=base64.urlsafe_b64encode(ind.encode()).decode().rstrip("="); path=f"urls/{uid}"
    d,e=req("GET","https://www.virustotal.com/api/v3/"+path,headers={"x-apikey":k})
    if e:return None,e
    a=(d.get("data") or {}).get("attributes") or {}; s=a.get("last_analysis_stats") or {}
    return {"reputation":a.get("reputation"),"malicious":s.get("malicious",0),"suspicious":s.get("suspicious",0),"harmless":s.get("harmless",0),"undetected":s.get("undetected",0),"categories":a.get("categories") or {}},None

def abuse(ind):
    k=secret("ABUSEIPDB_API_KEY")
    if not k:return None,"Not configured."
    ip=ipaddress.ip_address(ind)
    if not ip.is_global:return None,"Skipped: IP is not globally routable."
    d,e=req("GET","https://api.abuseipdb.com/api/v2/check",params={"ipAddress":str(ip),"maxAgeInDays":90},headers={"Key":k,"Accept":"application/json"})
    if e:return None,e
    a=(d.get("data") or {})
    return {"abuse_confidence_score":a.get("abuseConfidenceScore"),"total_reports":a.get("totalReports"),"last_reported_at":a.get("lastReportedAt")},None

def local(ind,t):
    s=[]
    if t=="IP Address":
        ip=ipaddress.ip_address(ind); s.append({"Signal":"IP scope","Value":"Global" if ip.is_global else "Non-global","Source":"Local","Meaning":"Routability classification."})
    elif t=="Domain":
        if "xn--" in ind:s.append({"Signal":"Punycode","Value":"Present","Source":"Local","Meaning":"IDN/punycode label detected."})
        if len(ind.split("."))>=5:s.append({"Signal":"Hostname depth","Value":len(ind.split(".")),"Source":"Local","Meaning":"Many domain labels."})
    else:
        p=urlparse(ind)
        if "xn--" in (p.hostname or "").lower():s.append({"Signal":"Punycode hostname","Value":"Present","Source":"Local","Meaning":"IDN/punycode hostname."})
        if p.port not in (None,80,443):s.append({"Signal":"Unusual port","Value":p.port,"Source":"Local","Meaning":"Non-standard HTTP/HTTPS port."})
        if len(ind)>300:s.append({"Signal":"Long URL","Value":len(ind),"Source":"Local","Meaning":"Unusually long URL."})
        if len(p.query)>500:s.append({"Signal":"Large query","Value":len(p.query),"Source":"Local","Meaning":"Large query component."})
    return {"signals":s}

def urlscan(ind):
    k=secret("URLSCAN_API_KEY")
    if not k:return None,"Not configured."
    vis=secret("URLSCAN_VISIBILITY") or "unlisted"
    if vis not in ("unlisted","public","private"):vis="unlisted"
    d,e=req("POST","https://urlscan.io/api/v1/scan/",headers={"API-Key":k,"Content-Type":"application/json"},json={"url":ind,"visibility":vis})
    if e:return None,e
    result=d.get("result") or d.get("api")
    if not result:return {"status":"submitted","visibility":vis},None
    for _ in range(6):
        time.sleep(3)
        x,err=req("GET",result,headers={"API-Key":k})
        if err=="Result not found.":continue
        if err:return {"status":"processing","result_url":result},err
        v=x.get("verdicts",{}).get("overall",{})
        return {"status":"complete","verdict":v.get("malicious"),"score":v.get("score"),"result_url":result},None
    return {"status":"processing","result_url":result,"message":"URLScan analysis is still processing."},None

def score(v,a,u,l):
    ext=0;s=0
    if v:
        ext+=1;s+=min(55,int(v.get("malicious",0))*6+int(v.get("suspicious",0))*2)
        if isinstance(v.get("reputation"),(int,float)) and v["reputation"]<0:s+=min(20,abs(v["reputation"])//10)
    if a:
        ext+=1;s+=min(45,round((a.get("abuse_confidence_score") or 0)*.45));s+=min(12,round(min(a.get("total_reports") or 0,50)*.25))
    if u:
        ext+=1
        if u.get("verdict") is True:s+=45
        if isinstance(u.get("score"),(int,float)) and u["score"]>0:s+=min(15,round(u["score"]/7))
    s+=min(20,len(l.get("signals",[]))*4)
    if not ext:return None
    return min(100,s if ext>1 else min(s,80))

def label(s):
    if s is None:return "Unknown / Insufficient Evidence"
    if s<=20:return "Low Risk"
    if s<=40:return "Moderate Risk"
    if s<=60:return "Suspicious"
    if s<=80:return "High Risk"
    return "Critical / Malicious"

def gemini(e):
    k=secret("GEMINI_API_KEY")
    if not k or genai is None:return None
    prompt="""You are the evidence-interpretation layer of a cybersecurity app. Analyze ONLY the supplied JSON. Never invent reputation, malware detections, WHOIS, DNS, geography, vendor detections, threat intelligence, or other facts. Missing data must be stated as unavailable. Do not change the score. Explain observed evidence, uncertainty, conflicts, and practical next steps. Use headings: Assessment, Evidence, Uncertainty, Recommended Next Steps.\n\nEVIDENCE:\n"""+__import__("json").dumps(e,indent=2,default=str)
    try:
        r=genai.Client(api_key=k).models.generate_content(model="gemini-2.5-flash",contents=prompt)
        return getattr(r,"text",None)
    except Exception:return None

def analyze_indicator(ind,t):
    v=a=u=None; errors=[]; eb={}
    l=local(ind,t)
    v,e=vt(ind,t)
    if e:errors.append("VirusTotal: "+e);eb["VirusTotal"]=e
    if t=="IP Address":
        a,e=abuse(ind)
        if e:errors.append("AbuseIPDB: "+e);eb["AbuseIPDB"]=e
    if t=="URL":
        u,e=urlscan(ind)
        if e:errors.append("URLScan: "+e);eb["URLScan"]=e
    s=score(v,a,u,l)
    evidence={"indicator":ind,"indicator_type":t,"virustotal":v,"abuseipdb":a,"urlscan":u,"local_analysis":l,"errors":errors}
    links={}
    if t=="IP Address":links["VirusTotal"]=f"https://www.virustotal.com/gui/ip-address/{quote(ind,safe='')}"
    if t=="Domain":links["VirusTotal"]=f"https://www.virustotal.com/gui/domain/{quote(ind,safe='')}"
    if t=="URL":
        uid=base64.urlsafe_b64encode(ind.encode()).decode().rstrip("=");links["VirusTotal"]=f"https://www.virustotal.com/gui/url/{uid}"
        if u and u.get("result_url"):links["URLScan"]=u["result_url"]
    signals=[]
    for src,data in [("VirusTotal",v),("AbuseIPDB",a),("URLScan",u)]:
        if data:
            for k,val in data.items():
                if val is not None and not isinstance(val,(dict,list)):signals.append({"Signal":k,"Value":val,"Source":src,"Meaning":"Provider-reported evidence."})
    signals+=l.get("signals",[])
    conflicts=[]
    if v and int(v.get("malicious",0) or 0)>0 and a and int(a.get("abuse_confidence_score",0) or 0)<10:conflicts.append("VirusTotal reports malicious detections while AbuseIPDB confidence is low.")
    if v and int(v.get("malicious",0) or 0)==0 and u and u.get("verdict") is True:conflicts.append("VirusTotal reports no malicious detections while URLScan reports a malicious verdict.")
    coverage="High" if sum(bool(x) for x in (v,a,u))>=2 else "Medium" if sum(bool(x) for x in (v,a,u))==1 else "Low"
    return {"indicator":ind,"indicator_type":t,"virustotal":v,"abuseipdb":a,"urlscan":u,"local":l,"score":s,"label":label(s),"coverage":coverage,"signals":signals,"conflicts":conflicts,"errors":errors,"errors_by_source":eb,"links":links,"evidence":evidence,"ai_analysis":gemini(e)}
