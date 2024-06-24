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
        """Parse JSON report.
        Checkov may return only one `check_type` (where the report is just a JSON)
        or more (where the report is an array of JSONs).
        To address all scenarios we force this method to return a list of JSON objects.

        :param json_output: JSON report
        :type json_output: file
        :return: JSON array of objects
        :rtype: list
        """
        try:
            data = json_output.read()
            try:
                deserialized = json.loads(str(data, "utf-8"))
            except BaseException:
                deserialized = json.loads(data)
        except BaseException:
            msg = "Invalid format"
            raise ValueError(msg)

        return (
            [deserialized] if not isinstance(deserialized, list) else deserialized
        )

    def get_items(self, tree, test, check_type):
        items = []

        failed_checks = tree.get("vulnerabilities", [])
        for node in failed_checks:
            item = self.get_item(node, test, check_type)
            if item:
                items.append(item)

        return items

    def get_item(self, vuln, test, check_type):
        title = vuln.get("id", "No title provided")
        description = f"Check Type: {check_type}\n"
        description += f"Description: {vuln.get('description', 'No description provided')}\n"
        if vuln.get("id"):
            description += f"Check Id: {vuln['id']}\n"

        file_path = None
        resource = None
        if "affects" in vuln and vuln["affects"]:
            affected = vuln["affects"][0]
            file_path = affected.get("ref")
            resource = affected.get("ref")

        # Map unsupported severity levels to supported ones
        severity = "Medium"
        if "ratings" in vuln and vuln["ratings"]:
            severity_value = vuln["ratings"][0].get("severity", "Medium").capitalize()
            if severity_value not in ['Info', 'Low', 'Medium', 'High', 'Critical']:
                severity = "Medium"
            else:
                severity = severity_value

        mitigation = ""

        references = ""
        if "advisories" in vuln and vuln["advisories"]:
            references = ", ".join([adv["url"] for adv in vuln["advisories"]])

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
