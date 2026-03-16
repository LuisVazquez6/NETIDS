from .llama_analyzer import analyze_alert


def soc_analysis(alert_dict):
    """
    Runs AI SOC analysis using local Llama model
    """

    ai_result = analyze_alert(alert_dict)

    alert_dict["ai_summary"] = ai_result.get("summary")
    alert_dict["ai_severity"] = ai_result.get("severity")
    alert_dict["ai_explanation"] = ai_result.get("explanation")
    alert_dict["ai_recommendation"] = ai_result.get("recommendation")

    return alert_dict