import base64
import ipaddress
import socket
import time
from urllib.parse import urlparse

import requests


TIMEOUT = 20
VT_API = "https://www.virustotal.com/api/v3"
ABUSE_API = "https://api.abuseipdb.com/api/v2"
URLSCAN_API = "https://urlscan.io/api/v1"


def _configured(key):
    return bool(key and key.strip())


def provider_status(VirusTotal="", AbuseIPDB="", URLScan="", Gemini=""):
    return {
        "VirusTotal": _configured(VirusTotal),
        "AbuseIPDB": _configured(AbuseIPDB),
        "URLScan": _configured(URLScan),
        "Gemini": _configured(Gemini),
    }


def _result(provider, configured, status, data=None, error=None, signals=None):
    return {
        "provider": provider,
        "configured": configured,
        "status": status,
        "data": data,
        "error": error,
        "signals": signals or [],
    }


def analyze_local(url):
    parsed = urlparse(url)
    host = parsed.hostname or ""
    signals = []
    resolved_ip = None

    if parsed.scheme != "https":
        signals.append("URL does not use HTTPS.")

    try:
        ascii_host = host.encode("idna").decode("ascii")
        if ascii_host.lower().startswith("xn--") or ".xn--" in ascii_host.lower():
            signals.append("Hostname contains IDN/punycode.")
    except Exception:
        pass

    if "@" in parsed.netloc:
        signals.append("URL contains @ in the authority section.")

    if len(url) > 250:
        signals.append("URL is unusually long.")

    redirect_params = {
        "url", "redirect", "redirect_url", "target", "dest",
        "destination", "next", "return", "returnurl", "continue"
    }

    params = {
        part.split("=", 1)[0].lower()
        for part in parsed.query.split("&")
        if part
    }

    found = sorted(params & redirect_params)
    if found:
        signals.append(
            "Redirect-like query parameters: " + ", ".join(found)
        )

    try:
        resolved_ip = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            addresses = socket.getaddrinfo(
                host,
                None,
                proto=socket.IPPROTO_TCP,
            )
            ips = sorted({row[4][0] for row in addresses})
            if ips:
                resolved_ip = ips[0]
        except Exception:
            pass

    if resolved_ip:
        try:
            ip_obj = ipaddress.ip_address(resolved_ip)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
            ):
                signals.append(
                    f"Resolved IP is not publicly routable: {resolved_ip}"
                )
        except ValueError:
            pass

    return {
        "hostname": host,
        "resolved_ip": resolved_ip,
        "scheme": parsed.scheme,
        "port": parsed.port,
        "query_parameter_count": len(params),
        "signals": signals,
    }


def _url_id(url):
    return base64.urlsafe_b64encode(
        url.encode()
    ).decode().rstrip("=")


def scan_virustotal(url, api_key):
    if not _configured(api_key):
        return _result(
            "VirusTotal",
            False,
            "Not configured — add VIRUSTOTAL_API_KEY",
        )

    headers = {
        "x-apikey": api_key,
        "accept": "application/json",
    }

    try:
        response = requests.get(
            f"{VT_API}/urls/{_url_id(url)}",
            headers=headers,
            timeout=TIMEOUT,
        )

        if response.status_code == 404:
            submit = requests.post(
                f"{VT_API}/urls",
                headers=headers,
                files={"url": (None, url)},
                timeout=TIMEOUT,
            )
            submit.raise_for_status()

            analysis_id = submit.json()["data"]["id"]

            analysis = None
            for _ in range(8):
                time.sleep(2)
                check = requests.get(
                    f"{VT_API}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=TIMEOUT,
                )
                check.raise_for_status()
                analysis = check.json()["data"]

                if (
                    analysis.get("attributes", {}).get("status")
                    == "completed"
                ):
                    break

            attrs = (analysis or {}).get("attributes", {})
            stats = attrs.get("stats", {})

            return _result(
                "VirusTotal",
                True,
                "Analysis completed"
                if attrs.get("status") == "completed"
                else "Analysis pending",
                data={
                    "analysis_id": analysis_id,
                    "stats": stats,
                },
                signals=_vt_signals(stats),
            )

        response.raise_for_status()

        data = response.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        return _result(
            "VirusTotal",
            True,
            "Existing report found",
            data={
                "id": data.get("id"),
                "reputation": attrs.get("reputation"),
                "stats": stats,
            },
            signals=_vt_signals(stats),
        )

    except requests.RequestException as exc:
        return _result(
            "VirusTotal",
            True,
            "Request failed",
            error=str(exc),
        )


def _vt_signals(stats):
    signals = []

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)

    if malicious:
        signals.append(
            f"VirusTotal malicious detections: {malicious}"
        )

    if suspicious:
        signals.append(
            f"VirusTotal suspicious detections: {suspicious}"
        )

    return signals


def check_abuseipdb(ip, api_key):
    if not _configured(api_key):
        return _result(
            "AbuseIPDB",
            False,
            "Not configured — add ABUSEIPDB_API_KEY",
        )

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return _result(
            "AbuseIPDB",
            True,
            "Invalid IP",
            error=f"Invalid IP: {ip}",
        )

    try:
        response = requests.get(
            f"{ABUSE_API}/check",
            headers={
                "Key": api_key,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
            },
            timeout=TIMEOUT,
        )

        response.raise_for_status()
        data = response.json().get("data", {})

        score = data.get("abuseConfidenceScore", 0)
        signals = []

        if score:
            signals.append(
                f"AbuseIPDB confidence score: {score}/100"
            )

        return _result(
            "AbuseIPDB",
            True,
            "IP report found",
            data=data,
            signals=signals,
        )

    except requests.RequestException as exc:
        return _result(
            "AbuseIPDB",
            True,
            "Request failed",
            error=str(exc),
        )


def scan_urlscan(url, api_key):
    if not _configured(api_key):
        return _result(
            "URLScan",
            False,
            "Not configured — add URLSCAN_API_KEY",
        )

    try:
        response = requests.post(
            f"{URLSCAN_API}/scan/",
            headers={
                "api-key": api_key,
                "Content-Type": "application/json",
            },
            json={
                "url": url,
                "visibility": "unlisted",
            },
            timeout=TIMEOUT,
        )

        response.raise_for_status()
        submitted = response.json()
        scan_id = submitted.get("uuid")

        if not scan_id:
            return _result(
                "URLScan",
                True,
                "Submitted but no scan ID returned",
                data=submitted,
            )

        result = None

        for _ in range(10):
            time.sleep(3)

            check = requests.get(
                f"https://urlscan.io/api/v1/result/{scan_id}/",
                timeout=TIMEOUT,
            )

            if check.status_code == 200:
                result = check.json()
                break

            if check.status_code not in (404, 429):
                check.raise_for_status()

        if result is None:
            return _result(
                "URLScan",
                True,
                "Scan submitted; result still pending",
                data={"scan_id": scan_id},
            )

        verdicts = result.get("verdicts", {})
        overall = verdicts.get("overall", {})
        signals = []

        if overall.get("malicious"):
            signals.append(
                "URLScan overall verdict is malicious."
            )

        return _result(
            "URLScan",
            True,
            "Scan result found",
            data={
                "scan_id": scan_id,
                "page": result.get("page", {}),
                "verdicts": verdicts,
                "stats": result.get("stats", {}),
            },
            signals=signals,
        )

    except requests.RequestException as exc:
        return _result(
            "URLScan",
            True,
            "Request failed",
            error=str(exc),
        )


def combine_assessment(local, virustotal, abuseipdb, urlscan):
    score = 0
    reasons = []

    vt_stats = (
        virustotal.get("data") or {}
    ).get("stats") or {}

    malicious = int(vt_stats.get("malicious", 0) or 0)
    suspicious = int(vt_stats.get("suspicious", 0) or 0)

    if malicious:
        score += min(70, malicious * 10)
        reasons.append(
            f"{malicious} VirusTotal malicious detection(s)"
        )

    if suspicious:
        score += min(20, suspicious * 5)
        reasons.append(
            f"{suspicious} VirusTotal suspicious detection(s)"
        )

    abuse_data = (
        (abuseipdb or {}).get("data") or {}
    )
    abuse_score = abuse_data.get("abuseConfidenceScore")

    if isinstance(abuse_score, (int, float)) and abuse_score:
        score += round(min(25, abuse_score * 0.25))
        reasons.append(
            f"AbuseIPDB score {abuse_score}/100"
        )

    if any(
        "malicious" in signal.lower()
        for signal in urlscan.get("signals", [])
    ):
        score += 30
        reasons.append("URLScan malicious verdict")

    local_signals = local.get("signals", [])
    score += min(10, len(local_signals) * 2)

    if local_signals:
        reasons.append(
            f"{len(local_signals)} local heuristic signal(s)"
        )

    configured = sum(
        1
        for source in (
            virustotal,
            abuseipdb,
            urlscan,
        )
        if source and source.get("configured")
    )

    if configured == 0:
        label = "Unknown"
    elif score >= 70:
        label = "High"
    elif score >= 30:
        label = "Medium"
    else:
        label = "Low"

    coverage = (
        "Good"
        if configured >= 2
        else "Partial"
        if configured == 1
        else "Low"
    )

    return {
        "score": min(score, 100),
        "score_label": label,
        "coverage": coverage,
        "provider_count": configured,
        "reasons": reasons,
    }
