import base64
import ipaddress
import json
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import streamlit as st


# ============================================================
# Cyber Sentinel AI - Standalone app.py
# This file intentionally contains the backend functions too,
# so it does NOT depend on a separate threat_sources.py file.
# ============================================================

REQUEST_TIMEOUT = (10, 30)
VT_BASE = "https://www.virustotal.com/api/v3"
ABUSE_BASE = "https://api.abuseipdb.com/api/v2"
URLSCAN_BASE = "https://urlscan.io/api/v1"
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"
GEMINI_TIMEOUT = (10, 60)
MAX_PROVIDER_RETRIES = 2


def get_secret(name):
    """Read a secret from Streamlit Cloud secrets first, then env vars."""
    try:
        value = st.secrets.get(name)
        if value:
            return str(value).strip()
    except Exception:
        pass

    value = os.getenv(name)
    return value.strip() if value else None


def get_vt_key():
    return get_secret("VT_API_KEY") or get_secret("VIRUSTOTAL_API_KEY")


def get_api_availability():
    return {
        "gemini": bool(
            get_secret("GEMINI_API_KEY")
            or get_secret("GOOGLE_API_KEY")
        ),
        "virustotal": bool(get_vt_key()),
        "abuseipdb": bool(get_secret("ABUSEIPDB_API_KEY")),
        "urlscan": bool(get_secret("URLSCAN_API_KEY")),
    }


def detect_indicator_type(value):
    value = (value or "").strip()

    try:
        ipaddress.ip_address(value)
        return "IP Address"
    except ValueError:
        pass

    candidate = value if "://" in value else "https://" + value

    try:
        parsed = urlparse(candidate)
        if not parsed.hostname:
            return "Custom Indicator"

        # An explicit http/https scheme means URL. A bare hostname
        # remains a Domain unless it contains a path/query/fragment.
        if "://" in value:
            return "URL"

        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            return "URL"

        return "Domain"
    except Exception:
        return "Custom Indicator"


def validate_indicator(value, indicator_type):
    value = (value or "").strip()

    if not value:
        return "", "Please enter an indicator."

    if indicator_type == "IP Address":
        try:
            ipaddress.ip_address(value)
            return value, None
        except ValueError:
            return "", "Invalid IPv4/IPv6 address."

    if indicator_type == "Domain":
        candidate = value.lower().rstrip(".")

        if "://" in candidate or "/" in candidate or "@" in candidate:
            return "", "Enter a domain only, for example: example.com"

        try:
            ipaddress.ip_address(candidate)
            return "", "This is an IP address. Select 'IP Address'."
        except ValueError:
            pass

        if len(candidate) > 253 or "." not in candidate:
            return "", "Invalid domain name."

        labels = candidate.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            for label in labels
        ):
            return "", "Invalid domain name."

        return candidate, None

    if indicator_type == "URL":
        candidate = value if "://" in value else "https://" + value

        try:
            parsed = urlparse(candidate)

            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                return "", "Invalid HTTP/HTTPS URL."

            if parsed.username or parsed.password:
                return "", "URLs containing usernames/passwords are not allowed."

            return candidate, None
        except Exception:
            return "", "Invalid HTTP/HTTPS URL."

    detected = detect_indicator_type(value)

    if detected == "Custom Indicator":
        return "", "Unsupported indicator. Use an IP address, domain, or HTTP/HTTPS URL."

    return validate_indicator(value, detected)



def _request_with_retries(method, url, headers=None, params=None, payload=None,
                          timeout=REQUEST_TIMEOUT, retries=MAX_PROVIDER_RETRIES):
    """Perform a provider request with bounded retries for transient failures."""
    last_error = None

    for attempt in range(retries + 1):
        try:
            response = requests.request(
                method,
                url,
                headers=headers or {},
                params=params,
                json=payload,
                timeout=timeout,
            )

            if response.status_code in (408, 425, 429, 500, 502, 503, 504):
                if attempt < retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue

            return response

        except (
            requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectTimeout,
            requests.exceptions.ConnectionError,
        ) as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            raise

    if last_error:
        raise last_error

    raise RuntimeError("Provider request failed without a response.")


def _raise_http_error(provider, response):
    detail = response.text[:700].replace("\n", " ")
    if response.status_code == 401:
        raise RuntimeError("{} authentication failed (HTTP 401).".format(provider))
    if response.status_code == 403:
        raise RuntimeError("{} access was forbidden (HTTP 403).".format(provider))
    if response.status_code == 429:
        raise RuntimeError("{} rate limit reached (HTTP 429).".format(provider))
    raise RuntimeError(
        "{} HTTP {}: {}".format(
            provider,
            response.status_code,
            detail,
        )
    )


def http_get_json(url, headers=None, params=None):
    response = _request_with_retries(
        "GET",
        url,
        headers=headers,
        params=params,
    )

    if not response.ok:
        _raise_http_error("Provider", response)

    try:
        return response.json()
    except ValueError:
        raise RuntimeError("Provider returned invalid JSON.")


def http_post_json(url, headers=None, payload=None):
    response = _request_with_retries(
        "POST",
        url,
        headers=headers,
        payload=payload,
    )

    if not response.ok:
        _raise_http_error("Provider", response)

    try:
        return response.json()
    except ValueError:
        raise RuntimeError("Provider returned invalid JSON.")



def virustotal_report(indicator, indicator_type):
    key = get_vt_key()

    if not key:
        raise RuntimeError("VirusTotal API key is not configured.")

    headers = {"x-apikey": key}

    if indicator_type == "IP Address":
        endpoint = "{}/ip_addresses/{}".format(
            VT_BASE,
            requests.utils.quote(indicator, safe=""),
        )

    elif indicator_type == "Domain":
        endpoint = "{}/domains/{}".format(
            VT_BASE,
            requests.utils.quote(indicator, safe=""),
        )

    elif indicator_type == "URL":
        encoded = base64.urlsafe_b64encode(
            indicator.encode("utf-8")
        ).decode("ascii").rstrip("=")
        endpoint = "{}/urls/{}".format(VT_BASE, encoded)

    else:
        raise RuntimeError("VirusTotal does not support this indicator type.")

    response = _request_with_retries(
        "GET",
        endpoint,
        headers=headers,
    )

    # A 404 from VirusTotal is a valid "no report found" outcome,
    # not a provider failure.
    if response.status_code == 404:
        return {
            "summary": "No VirusTotal report found for this indicator.",
            "status": "no_result",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total": 0,
            "reputation": None,
            "country": None,
            "as_owner": None,
            "categories": None,
            "last_analysis_date": None,
            "url": "https://www.virustotal.com/gui/home/search",
            "raw": {"status": "not_found"},
        }

    if not response.ok:
        _raise_http_error("VirusTotal", response)

    try:
        data = response.json()
    except ValueError:
        raise RuntimeError("VirusTotal returned invalid JSON.")

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats") or {}

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    total = malicious + suspicious + harmless + undetected

    if indicator_type == "IP Address":
        gui_path = "ip-address"
    elif indicator_type == "Domain":
        gui_path = "domain"
    else:
        gui_path = "url"

    return {
        "summary": "{} malicious, {} suspicious, {} harmless".format(
            malicious, suspicious, harmless
        ),
        "status": "found",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total": total,
        "reputation": attrs.get("reputation"),
        "country": attrs.get("country"),
        "as_owner": attrs.get("as_owner"),
        "categories": attrs.get("categories"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "url": "https://www.virustotal.com/gui/{}/{}".format(
            gui_path,
            indicator,
        ),
        "raw": data,
    }


def _public_ips_for_indicator(indicator, indicator_type):
    """Resolve a hostname/URL to a small set of public IPs for AbuseIPDB."""
    if indicator_type == "IP Address":
        try:
            ip = ipaddress.ip_address(indicator)
            return [indicator] if ip.is_global else []
        except ValueError:
            return []

    url = indicator if indicator_type == "URL" else "https://" + indicator
    hostname = urlparse(url).hostname

    if not hostname:
        return []

    try:
        addresses = socket.getaddrinfo(hostname, None)
    except Exception:
        return []

    result = []
    for item in addresses:
        try:
            candidate = item[4][0]
            ip = ipaddress.ip_address(candidate)
            if ip.is_global and candidate not in result:
                result.append(candidate)
        except Exception:
            continue

    return result[:3]


def abuseipdb_report(indicator, indicator_type="IP Address"):
    key = get_secret("ABUSEIPDB_API_KEY")

    if not key:
        raise RuntimeError("AbuseIPDB API key is not configured.")

    ips = _public_ips_for_indicator(indicator, indicator_type)

    if not ips:
        return {
            "summary": "No public IP could be resolved for AbuseIPDB lookup.",
            "status": "no_result",
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "country_code": None,
            "isp": None,
            "domain": None,
            "usage_type": None,
            "is_whitelisted": None,
            "last_reported_at": None,
            "resolved_ips": [],
            "url": "https://www.abuseipdb.com/",
            "raw": {"resolved_ips": []},
        }

    records = []

    for ip in ips:
        response = _request_with_retries(
            "GET",
            "{}/check".format(ABUSE_BASE),
            headers={
                "Key": key,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
            },
        )

        if not response.ok:
            _raise_http_error("AbuseIPDB", response)

        try:
            data = response.json().get("data", {})
        except ValueError:
            raise RuntimeError("AbuseIPDB returned invalid JSON.")

        records.append(data)

    best = max(
        records,
        key=lambda item: int(
            item.get("abuseConfidenceScore", 0) or 0
        ),
    )

    score = max(
        int(item.get("abuseConfidenceScore", 0) or 0)
        for item in records
    )
    reports = sum(
        int(item.get("totalReports", 0) or 0)
        for item in records
    )

    if indicator_type == "IP Address":
        summary = "Abuse confidence {}/100; {} reports in last 90 days".format(
            score,
            reports,
        )
    else:
        summary = (
            "Resolved {} public IP(s); highest abuse confidence {}/100"
        ).format(len(records), score)

    return {
        "summary": summary,
        "status": "found",
        "abuse_confidence_score": score,
        "total_reports": reports,
        "country_code": best.get("countryCode"),
        "isp": best.get("isp"),
        "domain": best.get("domain"),
        "usage_type": best.get("usageType"),
        "is_whitelisted": best.get("isWhitelisted"),
        "last_reported_at": best.get("lastReportedAt"),
        "resolved_ips": ips,
        "url": "https://www.abuseipdb.com/check/{}".format(ips[0]),
        "raw": {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "records": records,
        },
    }


def _urlscan_target(indicator, indicator_type):
    if indicator_type == "URL":
        return indicator

    if indicator_type == "Domain":
        return "https://{}/".format(indicator)

    if indicator_type == "IP Address":
        try:
            ip = ipaddress.ip_address(indicator)
            host = "[{}]".format(indicator) if ip.version == 6 else indicator
        except ValueError:
            host = indicator
        return "http://{}/".format(host)

    detected = detect_indicator_type(indicator)
    return _urlscan_target(indicator, detected)


def urlscan_report(indicator, indicator_type="URL"):
    key = get_secret("URLSCAN_API_KEY")

    if not key:
        raise RuntimeError("URLScan API key is not configured.")

    target_url = _urlscan_target(indicator, indicator_type)

    submission = http_post_json(
        "{}/scan/".format(URLSCAN_BASE),
        headers={
            "Content-Type": "application/json",
            "API-Key": key,
        },
        payload={
            "url": target_url,
            "visibility": "unlisted",
        },
    )

    uuid = submission.get("uuid")

    if not uuid:
        raise RuntimeError("URLScan did not return a scan UUID.")

    result_url = "https://urlscan.io/result/{}/".format(uuid)

    full_result = None

    # URLScan is asynchronous. Poll without treating the normal 404/425
    # processing responses as provider failures.
    for _ in range(10):
        time.sleep(2)

        response = _request_with_retries(
            "GET",
            "{}/result/{}/".format(URLSCAN_BASE, uuid),
            headers={"API-Key": key},
            retries=1,
        )

        if response.status_code == 200:
            try:
                full_result = response.json()
            except ValueError:
                raise RuntimeError("URLScan returned invalid JSON.")
            break

        if response.status_code not in (404, 425):
            _raise_http_error("URLScan", response)

    if not full_result:
        return {
            "summary": "URLScan accepted the scan; result is still processing.",
            "status": "processing",
            "uuid": uuid,
            "submitted_url": target_url,
            "url": result_url,
            "raw": submission,
        }

    verdicts = full_result.get("verdicts", {})
    overall = verdicts.get("overall", {})
    page = full_result.get("page", {})

    return {
        "summary": "Score {}; malicious={}".format(
            overall.get("score", 0),
            overall.get("malicious", False),
        ),
        "status": "found",
        "uuid": uuid,
        "submitted_url": target_url,
        "score": overall.get("score"),
        "malicious": overall.get("malicious"),
        "page": page,
        "url": result_url,
        "raw": full_result,
    }

def local_analysis(indicator, indicator_type):
    result = {"summary": "Local analysis completed."}

    if indicator_type == "IP Address":
        ip = ipaddress.ip_address(indicator)

        result.update(
            {
                "version": ip.version,
                "is_private": ip.is_private,
                "is_global": ip.is_global,
                "is_loopback": ip.is_loopback,
                "is_reserved": ip.is_reserved,
            }
        )

        try:
            result["reverse_dns"] = socket.gethostbyaddr(indicator)[0]
        except Exception:
            result["reverse_dns"] = None

        return result

    url = indicator if indicator_type == "URL" else "https://" + indicator
    parsed = urlparse(url)
    hostname = parsed.hostname

    result["hostname"] = hostname

    if not hostname:
        return result

    try:
        result["dns"] = sorted(
            set(
                item[4][0]
                for item in socket.getaddrinfo(hostname, None)
                if item[4]
            )
        )
    except Exception:
        result["dns"] = []

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=5,
        ) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as tls:
                certificate = tls.getpeercert()

                result["tls"] = {
                    "version": tls.version(),
                    "cipher": tls.cipher()[0] if tls.cipher() else None,
                    "subject": certificate.get("subject"),
                    "issuer": certificate.get("issuer"),
                }

    except Exception as exc:
        result["tls_error"] = str(exc)[:250]

    return result


def calculate_score(vt, abuse, urlscan):
    scores = []

    if vt:
        total = vt.get("total", 0)

        if total:
            malicious = vt.get("malicious", 0)
            suspicious = vt.get("suspicious", 0)

            score = (
                (malicious / total) * 100
                + (suspicious / total) * 40
            )

            scores.append(min(100, score))

    if abuse:
        scores.append(
            float(abuse.get("abuse_confidence_score", 0))
        )

    if urlscan:
        if urlscan.get("malicious") is True:
            scores.append(100.0)
        elif urlscan.get("score") is not None:
            scores.append(
                max(
                    0,
                    min(100, float(urlscan.get("score"))),
                )
            )

    if not scores:
        return None, "No provider evidence"

    score = int(round(max(scores)))

    if score >= 70:
        label = "High risk"
    elif score >= 30:
        label = "Suspicious"
    else:
        label = "Low risk"

    return score, label


def build_signals(vt, abuse, urlscan, local):
    rows = []

    if vt:
        rows.append(
            {
                "Source": "VirusTotal",
                "Signal": "Malicious detections",
                "Value": vt.get("malicious", 0),
            }
        )
        rows.append(
            {
                "Source": "VirusTotal",
                "Signal": "Suspicious detections",
                "Value": vt.get("suspicious", 0),
            }
        )

        if vt.get("reputation") is not None:
            rows.append(
                {
                    "Source": "VirusTotal",
                    "Signal": "Reputation",
                    "Value": vt.get("reputation"),
                }
            )

    if abuse:
        rows.append(
            {
                "Source": "AbuseIPDB",
                "Signal": "Abuse confidence",
                "Value": abuse.get("abuse_confidence_score", 0),
            }
        )
        rows.append(
            {
                "Source": "AbuseIPDB",
                "Signal": "Total reports",
                "Value": abuse.get("total_reports", 0),
            }
        )

        if abuse.get("isp"):
            rows.append(
                {
                    "Source": "AbuseIPDB",
                    "Signal": "ISP",
                    "Value": abuse.get("isp"),
                }
            )

    if urlscan:
        rows.append(
            {
                "Source": "URLScan",
                "Signal": "Malicious",
                "Value": urlscan.get("malicious"),
            }
        )

        if urlscan.get("score") is not None:
            rows.append(
                {
                    "Source": "URLScan",
                    "Signal": "Verdict score",
                    "Value": urlscan.get("score"),
                }
            )

    if local:
        for key in (
            "is_private",
            "is_global",
            "is_loopback",
            "is_reserved",
            "reverse_dns",
            "hostname",
        ):
            if key in local:
                rows.append(
                    {
                        "Source": "Local",
                        "Signal": key,
                        "Value": local.get(key),
                    }
                )

    return rows



def _fallback_ai_analysis(result):
    """Evidence-only fallback when Gemini cannot be reached."""
    indicator = result.get("indicator")
    indicator_type = result.get("indicator_type")
    score = result.get("score")
    label = result.get("label")

    parts = [
        "Gemini was not available for this scan, so this is an "
        "evidence-based local summary rather than a generated Gemini opinion.",
        "Indicator: {} ({})".format(indicator, indicator_type),
    ]

    if score is not None:
        parts.append(
            "Deterministic provider score: {} ({}) based only on returned provider evidence.".format(
                score,
                label,
            )
        )
    else:
        parts.append(
            "No deterministic provider score was produced because the available "
            "provider evidence did not contain a scoring signal."
        )

    vt = result.get("virustotal")
    if vt:
        parts.append(
            "VirusTotal: {}.".format(
                vt.get("summary", "evidence returned")
            )
        )

    abuse = result.get("abuseipdb")
    if abuse:
        parts.append(
            "AbuseIPDB: {}.".format(
                abuse.get("summary", "evidence returned")
            )
        )

    urlscan = result.get("urlscan")
    if urlscan:
        parts.append(
            "URLScan: {}.".format(
                urlscan.get("summary", "evidence returned")
            )
        )

    local = result.get("local")
    if local:
        if indicator_type == "IP Address":
            parts.append(
                "Local analysis: global={}, private={}, loopback={}, reverse DNS={}.".format(
                    local.get("is_global"),
                    local.get("is_private"),
                    local.get("is_loopback"),
                    local.get("reverse_dns"),
                )
            )
        else:
            parts.append(
                "Local analysis: hostname={}, resolved DNS entries={}.".format(
                    local.get("hostname"),
                    len(local.get("dns") or []),
                )
            )

    parts.append(
        "Limitations: provider coverage, rate limits, DNS state, and scan timing "
        "can affect the available evidence. Do not treat absence of detections as proof of safety."
    )

    return "\n\n".join(parts)


def gemini_analysis(result):
    """Generate an evidence-constrained Gemini analysis without the SDK."""
    key = get_secret("GEMINI_API_KEY") or get_secret("GOOGLE_API_KEY")

    if not key:
        result["errors"].append(
            "Gemini: API key is not configured."
        )
        return _fallback_ai_analysis(result)

    evidence = {
        "indicator": result.get("indicator"),
        "type": result.get("indicator_type"),
        "score": result.get("score"),
        "label": result.get("label"),
        "signals": result.get("signals"),
        "evidence": result.get("evidence"),
    }

    prompt = (
        "Act as a defensive cybersecurity analyst. "
        "Analyze ONLY the evidence supplied below. "
        "Do not invent facts. Clearly state uncertainty when evidence "
        "is missing. Give a concise assessment containing observed "
        "evidence, limitations, and defensive next steps. "
        "Do not provide offensive instructions.\n\n"
        + json.dumps(evidence, default=str)[:18000]
    )

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "maxOutputTokens": 700
        },
    }

    endpoint = (
        "{}/models/gemini-3.8-flash:generateContent".format(
            GEMINI_BASE
        )
    )

    try:
        response = None

        for attempt in range(2):
            try:
                response = requests.post(
                    endpoint,
                    headers={
                        "x-goog-api-key": key,
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=GEMINI_TIMEOUT,
                )
                break
            except (
                requests.exceptions.ReadTimeout,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
            ) as exc:
                if attempt == 1:
                    raise
                time.sleep(2)

        if response is None:
            raise RuntimeError("Gemini did not return a response.")

        if not response.ok:
            detail = response.text[:700].replace("\n", " ")
            raise RuntimeError(
                "Gemini HTTP {}: {}".format(
                    response.status_code,
                    detail,
                )
            )

        try:
            data = response.json()
        except ValueError:
            raise RuntimeError("Gemini returned invalid JSON.")

        texts = []

        for candidate in data.get("candidates", []) or []:
            content = candidate.get("content") or {}

            for part in content.get("parts", []) or []:
                text = part.get("text")

                if text:
                    texts.append(str(text))

        analysis = "\n\n".join(texts).strip()

        if analysis:
            return analysis

        prompt_feedback = data.get("promptFeedback")

        if isinstance(prompt_feedback, dict):
            block_reason = prompt_feedback.get("blockReason")

            if block_reason:
                raise RuntimeError(
                    "Gemini returned no text (block reason: {}).".format(
                        block_reason
                    )
                )

        raise RuntimeError(
            "Gemini returned a successful response but no text."
        )

    except Exception as exc:
        result["errors"].append(
            "Gemini: {}: {}".format(
                type(exc).__name__,
                str(exc)[:500],
            )
        )
        return _fallback_ai_analysis(result)


def analyze_indicator(indicator, indicator_type):
    result = {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "score": None,
        "label": "No provider evidence",
        "coverage": "0/4 providers",
        "virustotal": None,
        "abuseipdb": None,
        "urlscan": None,
        "local": None,
        "signals": [],
        "conflicts": [],
        "errors": [],
        "links": {},
        "evidence": {},
        "ai_analysis": None,
    }

    # Local analysis is always attempted.
    try:
        result["local"] = local_analysis(
            indicator,
            indicator_type,
        )
        result["evidence"]["local"] = result["local"]
    except Exception as exc:
        result["errors"].append(
            "Local analysis: {}: {}".format(
                type(exc).__name__,
                str(exc)[:300],
            )
        )

    # VirusTotal supports IP addresses, domains and URLs directly.
    if get_vt_key():
        try:
            result["virustotal"] = virustotal_report(
                indicator,
                indicator_type,
            )
            result["evidence"]["virustotal"] = result["virustotal"]
            result["links"]["VirusTotal"] = result["virustotal"]["url"]
        except Exception as exc:
            result["errors"].append(
                "VirusTotal: {}: {}".format(
                    type(exc).__name__,
                    str(exc)[:300],
                )
            )
    else:
        result["errors"].append(
            "VirusTotal: API key is not configured."
        )

    # AbuseIPDB is an IP reputation service. For domains/URLs we resolve
    # public IPs first and clearly mark the returned evidence as resolved-IP
    # evidence inside the data payload.
    if get_secret("ABUSEIPDB_API_KEY"):
        try:
            result["abuseipdb"] = abuseipdb_report(
                indicator,
                indicator_type,
            )
            result["evidence"]["abuseipdb"] = result["abuseipdb"]
            result["links"]["AbuseIPDB"] = result["abuseipdb"]["url"]
        except Exception as exc:
            result["errors"].append(
                "AbuseIPDB: {}: {}".format(
                    type(exc).__name__,
                    str(exc)[:300],
                )
            )
    else:
        result["errors"].append(
            "AbuseIPDB: API key is not configured."
        )

    # URLScan scans URLs. For a domain or IP we construct a public HTTP(S)
    # target solely for the provider submission; the original indicator
    # remains unchanged everywhere in the UI.
    if get_secret("URLSCAN_API_KEY"):
        try:
            result["urlscan"] = urlscan_report(
                indicator,
                indicator_type,
            )
            result["evidence"]["urlscan"] = result["urlscan"]
            result["links"]["URLScan"] = result["urlscan"]["url"]
        except Exception as exc:
            result["errors"].append(
                "URLScan: {}: {}".format(
                    type(exc).__name__,
                    str(exc)[:300],
                )
            )
    else:
        result["errors"].append(
            "URLScan: API key is not configured."
        )

    result["signals"] = build_signals(
        result["virustotal"],
        result["abuseipdb"],
        result["urlscan"],
        result["local"],
    )

    result["score"], result["label"] = calculate_score(
        result["virustotal"],
        result["abuseipdb"],
        result["urlscan"],
    )

    providers = sum(
        bool(result[key])
        for key in (
            "virustotal",
            "abuseipdb",
            "urlscan",
            "local",
        )
    )

    result["coverage"] = "{}/4 providers returned evidence".format(
        providers
    )

    result["ai_analysis"] = gemini_analysis(result)

    return result

# ============================================================
# UI
# ============================================================

st.set_page_config(
    page_title="Cyber Sentinel AI",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
    .stApp{background:#081421;color:#F5F7FA}
    .stSidebar{background:#102235}
    .block-container{max-width:1400px;padding-top:2rem}
    .hero{background:#102235;border:1px solid #2F81F7;border-radius:18px;padding:25px;margin-bottom:20px}
    .card{background:#142A3D;border:1px solid #29445c;border-radius:14px;padding:18px;min-height:120px}
    .muted{color:#AAB7C4}
    </style>
    """,
    unsafe_allow_html=True,
)


if "history" not in st.session_state:
    st.session_state.history = []

if "result" not in st.session_state:
    st.session_state.result = None


def card(title, value, sub=""):
    st.markdown(
        '<div class="card">'
        '<div class="muted">{}</div>'
        '<h2>{}</h2>'
        '<div class="muted">{}</div>'
        '</div>'.format(title, value, sub),
        unsafe_allow_html=True,
    )


def show_result(result):
    st.subheader("Threat Assessment")

    a, b, c, d = st.columns(4)

    with a:
        card("Indicator", result["indicator"])

    with b:
        card("Type", result["indicator_type"])

    with c:
        card(
            "Threat Score",
            result["score"]
            if result["score"] is not None
            else "Unknown",
            result["label"],
        )

    with d:
        card(
            "Evidence Coverage",
            result["coverage"],
            "Provider availability",
        )

    if result["score"] is not None:
        st.progress(
            max(0, min(100, result["score"])) / 100
        )

    if result["conflicts"]:
        st.warning(
            "Conflicting evidence: "
            + "; ".join(result["conflicts"])
        )

    st.subheader("Threat Intelligence Sources")

    cols = st.columns(4)

    for col, name, key in zip(
        cols,
        ["VirusTotal", "AbuseIPDB", "URLScan", "Local Analysis"],
        ["virustotal", "abuseipdb", "urlscan", "local"],
    ):
        with col:
            data = result.get(key)

            if data:
                card(
                    name,
                    "Evidence available",
                    data.get("summary", "")
                    if isinstance(data, dict)
                    else "",
                )
            else:
                card(
                    name,
                    "Unavailable / No result",
                )

    st.subheader("Security Signals")

    if result["signals"]:
        st.dataframe(
            result["signals"],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info(
            "No additional security signals were returned."
        )

    st.subheader("AI Security Analysis")

    st.markdown(
        result.get("ai_analysis")
        or "Gemini is not configured or did not return an analysis."
    )

    links = result.get("links", {})

    if links:
        st.subheader("Official External Results")

        for name, url in links.items():
            st.markdown(
                "- [{}]({})".format(name, url)
            )

    with st.expander("Technical Evidence JSON"):
        st.json(result["evidence"])

    if result["errors"]:
        with st.expander("Provider / Processing Notes"):
            for error in result["errors"]:
                st.warning(error)


page = st.sidebar.radio(
    "Navigation",
    ["Scanner", "Scan History", "About", "Settings"],
)

st.sidebar.caption(
    "Evidence-driven threat intelligence"
)


if page == "Scanner":
    st.markdown(
        '<div class="hero">'
        '<h1>🛡️ Cyber Sentinel AI</h1>'
        '<p>Intelligent Threat Detection. Safer Digital Decisions.</p>'
        '</div>',
        unsafe_allow_html=True,
    )

    kind = st.selectbox(
        "Indicator Type",
        [
            "IP Address",
            "URL",
            "Domain",
            "Custom Indicator",
        ],
    )

    placeholders = {
        "IP Address": "8.8.8.8",
        "URL": "https://example.com/path",
        "Domain": "example.com",
        "Custom Indicator": "IP, domain, or HTTP/HTTPS URL",
    }

    value = st.text_input(
        "Indicator",
        placeholder=placeholders[kind],
    )

    if kind == "URL":
        st.warning(
            "URLScan submission shares the URL with URLScan. "
            "Never submit credentials, tokens, private URLs, "
            "or sensitive data."
        )

    if st.button(
        "🔍 Scan Indicator",
        type="primary",
        use_container_width=True,
    ):
        detected = (
            detect_indicator_type(value)
            if kind == "Custom Indicator"
            else kind
        )

        normalized, error = validate_indicator(
            value,
            detected,
        )

        if error:
            st.error(error)

        else:
            with st.status(
                "Running security analysis...",
                expanded=True,
            ) as status:
                st.write("Validating indicator")
                st.write("Collecting available threat intelligence")

                result = analyze_indicator(
                    normalized,
                    detected,
                )

                st.write(
                    "Normalizing evidence and calculating deterministic score"
                )
                st.write(
                    "Generating evidence-constrained AI interpretation"
                )

                status.update(
                    label="Scan completed",
                    state="complete",
                    expanded=False,
                )

            result["scanned_at"] = datetime.now(
                timezone.utc
            ).isoformat()

            st.session_state.result = result

            st.session_state.history.insert(
                0,
                {
                    "time": result["scanned_at"],
                    "indicator": result["indicator"],
                    "type": result["indicator_type"],
                    "score": result["score"],
                    "status": result["label"],
                },
            )

    if st.session_state.result:
        st.divider()
        show_result(st.session_state.result)


elif page == "Scan History":
    st.markdown(
        '<div class="hero">'
        '<h1>🛡️ Scan History</h1>'
        '<p>Session-only results.</p>'
        '</div>',
        unsafe_allow_html=True,
    )

    if st.session_state.history:
        st.dataframe(
            st.session_state.history,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No scans in this session.")

    if st.button("Clear History"):
        st.session_state.history = []
        st.session_state.result = None
        st.rerun()


elif page == "About":
    st.markdown(
        '<div class="hero">'
        '<h1>🛡️ About Cyber Sentinel AI</h1>'
        '<p>Intelligent Threat Detection. Safer Digital Decisions.</p>'
        '</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        "Cyber Sentinel AI combines local validation with optional "
        "VirusTotal, AbuseIPDB, URLScan and Gemini evidence interpretation."
    )

    st.info(
        "Threat intelligence may be incomplete or delayed. "
        "This tool is an analysis aid, not a guarantee of safety."
    )

    st.warning(
        "External providers may receive submitted indicators. "
        "Do not submit credentials, tokens, private URLs or sensitive data."
    )


else:
    st.markdown(
        '<div class="hero">'
        '<h1>⚙️ Settings</h1>'
        '<p>Integration status. Secret values are never displayed.</p>'
        '</div>',
        unsafe_allow_html=True,
    )

    availability = get_api_availability()

    cols = st.columns(4)

    for col, name, key in zip(
        cols,
        ["Gemini", "VirusTotal", "AbuseIPDB", "URLScan"],
        ["gemini", "virustotal", "abuseipdb", "urlscan"],
    ):
        with col:
            card(
                name,
                "Connected"
                if availability[key]
                else "Not configured",
            )

    st.info(
        "Streamlit Cloud: add the API keys under "
        "App Settings → Secrets. Expected names: "
        "VT_API_KEY, ABUSEIPDB_API_KEY, URLSCAN_API_KEY, "
        "GEMINI_API_KEY."
    )
