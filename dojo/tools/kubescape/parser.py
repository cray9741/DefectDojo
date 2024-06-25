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
                    formatted.append(f"{'  ' * indent}{key}: {value}")
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

    def get_findings(self, filename, test):
        findings = []
        try:
            data = json.load(filename)
        except ValueError:
            data = {}

        for control_id, control_data in data.get("summaryDetails", {}).get("controls", {}).items():
            control_name = control_data.get("name", "Unnamed Control")
            control_status = control_data.get("status", "N/A")
            control_compliance_score = control_data.get("complianceScore", "N/A")
            control_score = control_data.get("score", 0)
            severity = self.map_severity(control_score)

            for resource in data.get("resources", []):
                resource_id = resource.get("resourceID", "N/A")
                resource_object = resource.get("object", {})

                description = f"{control_name}\n\n"
                description += f"**resourceID:** {resource_id}\n\n"
                description += f"**resource object:**\n{self.format_resource_object(resource_object)}\n\n"
                description += f"**controlID:** {control_id}\n\n"
                description += f"**status:** {control_status}\n\n"
                description += f"**complianceScore:** {control_compliance_score}\n\n"

                find = Finding(
                    title=str(control_id),
                    test=test,
                    description=description,
                    severity=severity,
                    static_finding=True
                )
                findings.append(find)

        return findings

