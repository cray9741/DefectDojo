import json
from dojo.models import Finding


class KubescapeParser:
    def get_scan_types(self):
        return ["Kubescape JSON Importer"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Import result of Kubescape JSON output."

    def format_resource_object(self, obj, indent=0):
        formatted = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, (dict, list)):
                    formatted.append(f"{'  ' * indent}{key}:")
                    formatted.append(self.format_resource_object(value, indent + 1))
                else:
                    formatted.append(f"{'  ' * (indent + 1)}{value}")
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    formatted.append(self.format_resource_object(item, indent + 1))
                else:
                    formatted.append(f"{'  ' * indent}- {item}")
        else:
            formatted.append(f"{'  ' * indent}{obj}")
        return "\n".join(formatted)

    def map_severity(self, score):
        if score >= 7:
            return "High"
        elif score >= 4:
            return "Medium"
        elif score >= 0:
            return "Low"
        else:
            return "Info"

    def get_findings(self, file, test):
        findings = []
        seen_findings = set()  # Set to keep track of unique findings

        try:
            data = json.load(file)
        except (ValueError, FileNotFoundError):
            return findings

        resources = data.get("resources", [])
        controls = data.get("summaryDetails", {}).get("controls", {})

        for control_id, control_data in controls.items():
            control_status = control_data.get("status", "N/A").lower()
            if control_status == "passed":
                continue  # Skip entries with status "passed"

            control_name = control_data.get("name", "Unnamed Control")
            control_compliance_score = control_data.get("complianceScore", "N/A")
            control_score = control_data.get("score", 0)
            severity = self.map_severity(control_score)

            for resource in resources:
                resource_id = resource.get("resourceID", "N/A")
                resource_object = resource.get("object", {})

                # Create a unique key for the finding
                finding_key = (control_id, resource_id)
                if finding_key in seen_findings:
                    continue  # Skip duplicate findings

                seen_findings.add(finding_key)  # Mark this finding as seen

                description = (
                    f"{control_name}\n\n"
                    f"**resourceID:** {resource_id}\n\n"
                    f"**resource object:**\n{self.format_resource_object(resource_object)}\n\n"
                    f"**controlID:** {control_id}\n\n"
                    f"**status:** {control_status}\n\n"
                    f"**complianceScore:** {control_compliance_score}\n\n"
                )

                findings.append(Finding(
                    title=str(control_id),
                    test=test,
                    description=description,
                    severity=severity,
                    static_finding=True
                ))

        return findings
