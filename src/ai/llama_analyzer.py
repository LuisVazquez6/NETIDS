import json
import re
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.2:3b"

def build_prompt(alert: dict) -> str:
    atype       = alert.get("alert_type", "UNKNOWN")
    severity    = alert.get("severity", "UNKNOWN")
    src_ip      = alert.get("src_ip", "unknown")
    dst_ip      = alert.get("dst_ip", "unknown")
    dst_port    = alert.get("dst_port", "unknown")
    proto       = alert.get("proto", "unknown")
    mitre       = alert.get("mitre_technique", "unknown")
    details     = alert.get("details", {})
    enrichment  = alert.get("enrichment", {})

    src_private = enrichment.get("src_is_private", True)
    dst_service = enrichment.get("dst_service", "") or proto
    src_dns     = enrichment.get("src_reverse_dns", "")

    lines = [
        f"Alert type : {atype}",
        f"Severity   : {severity}",
        f"MITRE      : {mitre}",
        f"Source     : {src_ip} ({'internal' if src_private else 'EXTERNAL'})",
    ]
    if src_dns:
        lines.append(f"Src host   : {src_dns}")
    lines.append(f"Destination: {dst_ip}:{dst_port} ({dst_service})")
    for k, v in details.items():
        if k != "thresholds":
            lines.append(f"{k}: {v}")

    context = "\n".join(lines)

    return f"""You are a SOC analyst writing a brief alert report. Respond with ONLY the JSON below — no extra text, no markdown.

Alert details:
{context}

Example of the exact response format:
{{"summary": "192.168.1.5 is brute-forcing SSH on 10.0.0.2", "severity": "HIGH", "explanation": "30 SYN packets sent to port 22 within 30 seconds, consistent with automated credential stuffing.", "recommendation": "Block 192.168.1.5 at the firewall and review /var/log/auth.log for failed logins."}}

Now write the same JSON for the alert above. Use the real IPs. Output only the JSON, nothing else.""".strip()


def _extract_json(text: str) -> dict:
    """Parse JSON from model output, handling markdown code fences."""
    text = text.strip()
    # strip ```json ... ``` or ``` ... ``` wrappers
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        text = match.group(1)
    # fallback: find first {...} block
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        text = match.group(0)
    return json.loads(text)


def analyze_alert(alert: dict) -> dict:
    prompt = build_prompt(alert)

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=60)
        response.raise_for_status()
        raw_text = response.json().get("response", "").strip()

        try:
            parsed = _extract_json(raw_text)
            return {
                "summary":        parsed.get("summary",        "No summary provided"),
                "severity":       parsed.get("severity",       "MEDIUM"),
                "explanation":    parsed.get("explanation",    "No explanation provided"),
                "recommendation": parsed.get("recommendation", "No recommendation provided"),
                "ai_raw":         raw_text,
            }
        except (json.JSONDecodeError, AttributeError):
            return {
                "summary":        "AI returned unparseable output",
                "severity":       "MEDIUM",
                "explanation":    raw_text[:300],
                "recommendation": "Review alert manually",
                "ai_raw":         raw_text,
            }

    except requests.RequestException as e:
        return {
            "summary":        "AI analysis unavailable",
            "severity":       "MEDIUM",
            "explanation":    str(e),
            "recommendation": "Check Ollama service is running (ollama serve)",
            "ai_raw":         "",
        }