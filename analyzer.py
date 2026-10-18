class Analyzer:
    SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}

    def __init__(self, findings):
        self.findings = findings

    def deduplicate(self):
        unique_findings = {}
        for finding in self.findings:
            key = (finding["title"], finding["evidence"])
            if key not in unique_findings:
                unique_findings[key] = finding
        self.findings = list(unique_findings.values())

    def sort_by_severity(self):
        self.findings.sort(key=lambda x: self.SEVERITY_ORDER.get(x["severity"], 0), reverse=True)

    def get_summary(self):
        summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for finding in self.findings:
            if finding["severity"] in summary:
                summary[finding["severity"]] += 1
        return summary
