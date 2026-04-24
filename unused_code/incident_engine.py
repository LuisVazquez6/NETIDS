from collection import defaultdict
from typing import Dict, List
from modeling import Alert

class IncidentEngine:
    def __init__(self):
        self.incidents: Dict[str, List[Alert]] = defaultdict(list)

    def process(self, alert: Alert):
        key = alert.src_ip:
        self.incident[key].append(alert)
    
    def get_incident(self):
        results = []

        for src_ip, alerts in self.incidents.items():
            severity = "LOW"

            if any(a.severity == "HIGH" for a in alerts):
                severity = "HIGH"
            elif any(a.severity == "MEDIUM" for a in alerts):
                severity = "MEDIUM"
            
            results.append({
                "src_ip": src_ip,
                "alert_count": len(alerts),
                "severity": severity,
                "types": list(set(a.alert_type for a in alerts))
            })

        return results 
