def gemini_analysis(
    url,
    local,
    virustotal,
    abuseipdb,
    urlscan,
    api_key,
):
    if not api_key:
        return {
            "configured": False,
            "text": None,
            "error": None,
        }

    try:
        from google import genai
    except ImportError:
        return {
            "configured": True,
            "text": None,
            "error": (
                "google-genai is not installed. "
                "Run: pip install -r requirements.txt"
            ),
        }

    prompt = f"""
You are a defensive cybersecurity analyst.

Analyze ONLY the evidence supplied below.
Do not invent detections.
Do not say a URL is safe merely because a provider has no result.
Clearly distinguish missing evidence from clean evidence.

Give:
1. Observed evidence
2. Missing evidence
3. Risk interpretation
4. Recommended defensive next step

URL:
{url}

Local analysis:
{local}

VirusTotal:
{virustotal}

AbuseIPDB:
{abuseipdb}

URLScan:
{urlscan}
"""

    try:
        client = genai.Client(api_key=api_key)

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )

        return {
            "configured": True,
            "text": getattr(response, "text", None),
            "error": None,
        }

    except Exception as exc:
        return {
            "configured": True,
            "text": None,
            "error": f"Gemini request failed: {exc}",
        }
