import json
from dojo.models import Finding

class CheckovParser:
    def get_scan_types(self):
        return ["Checkov Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Checkov Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON reports of Infrastructure as Code vulnerabilities."

    def get_findings(self, json_output, test):
        findings = []
        if json_output:
            deserialized = self.parse_json(json_output)
            for tree in deserialized:
                check_type = tree.get("check_type", "")
                findings += self.get_items(tree, test, check_type)

        return findings

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                deserialized = json.loads(str(data, "utf-8"))
            except BaseException:
                deserialized = json.loads(data)
        except BaseException:
            msg = "Invalid format"
            raise ValueError(msg)

        return [deserialized] if not isinstance(deserialized, list) else deserialized

    def get_items(self, tree, test, check_type):
        items = []

        # Extract failed checks from the JSON structure
        failed_checks = tree.get("results", {}).get("failed_checks", [])
        for node in failed_checks:
            item = self.get_item(node, test, check_type)
            if item:
                items.append(item)

        return items

    def get_item(self, vuln, test, check_type):
        title = vuln.get("check_id", "No title provided")
        description = f"Check Type: {check_type}\n"
        description += f"Check Name: {vuln.get('check_name', 'No check name provided')}\n"
        description += f"Result: {vuln.get('check_result', {}).get('result', 'No result provided')}\n"
        if vuln.get("check_id"):
            description += f"Check Id: {vuln['check_id']}\n"

        file_path = vuln.get("file_path")
        resource = vuln.get("resource")

        # Set severity based on ratings, default to Medium if not provided
        severity = "Medium"
        severity_value = vuln.get("severity", "Medium")
        if severity_value:
            severity_value = severity_value.capitalize()
            if severity_value in ['Info', 'Low', 'Medium', 'High', 'Critical']:
                severity = severity_value

        mitigation = ""

        references = vuln.get("guideline", "")

        return Finding(
            title=title,
            test=test,
            description=description,
            severity=severity,
            mitigation=mitigation,
            references=references,
            file_path=file_path,
            line=None,
            component_name=resource,
            static_finding=True,
            dynamic_finding=False,
        )
