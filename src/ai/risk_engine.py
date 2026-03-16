import time


class RiskEngine:
    """
    Converts anomaly scores into alert severity and builds a NETIDS-ready alert.
    Also applies a cooldown so the same source doesn't spam alerts constantly.
    """

    def __init__(self, cooldown_seconds=30):
        self.cooldown_seconds = cooldown_seconds
        self.last_alert_time = {}

    def _severity_from_score(self, score):
        if score <= -0.30:
            return "high"
        if score <= -0.20:
            return "medium"
        return "low"

    def should_alert(self, src_ip):
        now = time.time()
        last_time = self.last_alert_time.get(src_ip, 0)

        if now - last_time < self.cooldown_seconds:
            return False

        self.last_alert_time[src_ip] = now
        return True

    def build_alert(self, features, ai_result):
        src_ip = features.get("src_ip", "unknown")
        dst_ip = features.get("dst_ip", "unknown")
        score = ai_result["score"]

        if not self.should_alert(src_ip):
            return None

        severity = self._severity_from_score(score)

        return {
            "timestamp": time.time(),
            "alert_type": "AI_ANOMALY",
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": features.get("proto", 0),
            "score": score,
            "details": {
                "message": "AI anomaly detected from traffic behavior baseline deviation",
                "feature_snapshot": features,
            },
        }