import csv
import hashlib
import io
import json
import re
import sys
import textwrap
from datetime import date

from dojo.models import Finding


class AWSProwlerParser:
    def get_scan_types(self):
        return ["AWS Prowler Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AWS Prowler Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Export of AWS Prowler in CSV or JSON format."

    def get_findings(self, file, test):
        if file.name.lower().endswith(".csv"):
            return self.process_csv(file, test)
        elif file.name.lower().endswith(".json"):
            return self.process_json(file, test)
        else:
            msg = "Unknown file format"
            raise ValueError(msg)

    def process_csv(self, file, test):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        csv.field_size_limit(int(sys.maxsize / 10))  # the request/resp are big
        reader = csv.DictReader(io.StringIO(content))
        dupes = {}

        account = None

        for row in reader:
            # Getting all available fields from the Prowler CSV
            # Fields in order of appearance
            row.get("PROFILE")
            account = row.get("ACCOUNT_NUM")
            region = row.get("REGION")
            title_id = row.get("TITLE_ID")
            result = row.get("CHECK_RESULT")
            row.get("ITEM_SCORED")
            level = row.get("ITEM_LEVEL")
            title_text = row.get("TITLE_TEXT")
            result_extended = row.get("CHECK_RESULT_EXTENDED")
            asff_compliance_type = row.get("CHECK_ASFF_COMPLIANCE_TYPE")
            severity = row.get("CHECK_SEVERITY")
            aws_service_name = row.get("CHECK_SERVICENAME")
            asff_resource_type = row.get("CHECK_ASFF_RESOURCE_TYPE")
            asff_type = row.get("CHECK_ASFF_TYPE")
            impact = row.get("CHECK_RISK")
            mitigation = row.get("CHECK_REMEDIATION")
            documentation = row.get("CHECK_DOC")
            security_domain = row.get("CHECK_CAF_EPIC")
            # get prowler check number, useful for exceptions
            prowler_check_number = re.search(r"\[(.*?)\]", title_text).group(1)
            # remove '[check000] ' at the start of each title
            # title = re.sub(r"\[.*\]\s", "", result_extended)
            control = re.sub(r"\[.*\]\s", "", title_text)
            sev = self.getCriticalityRating(result, level, severity)
            if result == "INFO" or result == "PASS":
                active = False
            else:
                active = True

            # creating description early will help with duplication control
            if not level:
                level = ""
            else:
                level = ", " + level
            description = (
                "**Issue:** "
                + str(result_extended)
                + "\n**Control:** "
                + str(control)
                + "\n**AWS Account:** "
                + str(account)
                + " | **Region:** "
                + str(region)
                + "\n**CIS Control:** "
                + str(title_id)
                + str(level)
                + "\n**Prowler check:** "
                + str(prowler_check_number)
                + "\n**AWS Service:** "
                + str(aws_service_name)
                + "\n**ASFF Resource Type:** "
                + str(asff_resource_type)
                + "\n**ASFF Type:** "
                + str(asff_type)
                + "\n**ASFF Compliance Type:** "
                + str(asff_compliance_type)
                + "\n**Security Domain:** "
                + str(security_domain)
            )

            # improving key to get duplicates
            dupe_key = hashlib.sha256(
                (sev + "|" + region + "|" + result_extended).encode("utf-8")
            ).hexdigest()
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if description is not None:
                    find.description += description + "\n\n"
                find.nb_occurences += 1
            else:
                find = Finding(
                    active=active,
                    title=textwrap.shorten(result_extended, 150),
                    cwe=1032,  # Security Configuration Weaknesses, would like to fine tune
                    test=test,
                    description=description,
                    severity=sev,
                    references=documentation,
                    static_finding=True,
                    dynamic_finding=False,
                    nb_occurences=1,
                    mitigation=mitigation,
                    impact=impact,
                )
                dupes[dupe_key] = find

        return list(dupes.values())

    def process_json(self, file, test):
        dupes = {}

        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {e}")

        for deserialized in data:
            # Debugging the actual data to understand why findings are not processed
            print(f"Processing finding: {deserialized}")

            status_code = deserialized.get("status_code")
            print(f"Status Code: {status_code}")  # Debug statement
            if not status_code or status_code.upper() not in ["FAIL", "MANUAL"]:
                continue

            account = deserialized.get("cloud", {}).get("account", {}).get("uid")
            region = deserialized.get("cloud", {}).get("region")
            title_id = deserialized.get("finding_info", {}).get("control_id")
            level = deserialized.get("severity")
            title_text = deserialized.get("finding_info", {}).get("title")
            result_extended = deserialized.get("finding_info", {}).get("desc")
            asff_compliance_type = deserialized.get("unmapped", {}).get("compliance")
            severity = deserialized.get("severity")
            aws_service_name = deserialized.get("resources", [{}])[0].get("group", {}).get("name")
            impact = deserialized.get("risk_details")
            mitigation = deserialized.get("remediation", {}).get("desc")
            documentation = "\n".join(deserialized.get("remediation", {}).get("references", []))
            security_domain = deserialized.get("metadata", {}).get("event_code")
            timestamp = deserialized.get("event_time")
            # get prowler check number, useful for exceptions
            prowler_check_number = re.search(r"\[(.*?)\]", title_text).group(1) if title_text and re.search(r"\[(.*?)\]", title_text) else None
            control = re.sub(r"\[.*\]\s", "", title_text) if title_text else ""
            sev = self.getCriticalityRating(status_code, level, severity)

            # creating description early will help with duplication control
            if not level:
                level = ""
            else:
                level = ", " + level
            description = (
                "**Issue:** "
                + str(result_extended)
                + "\n**Control:** "
                + str(control)
                + "\n**AWS Account:** "
                + str(account)
                + " | **Region:** "
                + str(region)
                + "\n**CIS Control:** "
                + str(title_id)
                + str(level)
                + "\n**Prowler check:** "
                + str(prowler_check_number)
                + "\n**AWS Service:** "
                + str(aws_service_name)
                + "\n**ASFF Compliance Type:** "
                + str(asff_compliance_type)
                + "\n**Security Domain:** "
                + str(security_domain)
            )

            # improving key to get duplicates
            dupe_key = hashlib.sha256(
                (sev + "|" + region + "|" + result_extended).encode("utf-8")
            ).hexdigest()
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if description is not None:
                    find.description += description + "\n\n"
                find.nb_occurences += 1
            else:
                find = Finding(
                    title=textwrap.shorten(result_extended, 150),
                    cwe=1032,  # Security Configuration Weaknesses, would like to fine tune
                    test=test,
                    description=description,
                    severity=sev,
                    references=documentation,
                    date=date.fromisoformat(timestamp[:10]),
                    static_finding=True,
                    dynamic_finding=False,
                    nb_occurences=1,
                    mitigation=mitigation,
                    impact=impact,
                )
                dupes[dupe_key] = find

        print(f"Total findings processed: {len(dupes)}")  # Debug statement
        return list(dupes.values())

    def formatview(self, depth):
        if depth > 1:
            return "* "
        else:
            return ""

    # Criticality rating
    def getCriticalityRating(self, result, level, severity):
        criticality = "Info"
        if result == "INFO" or result == "PASS":
            criticality = "Info"
        elif result == "FAIL":
            if severity:
                # control is failing but marked as Info so we want to mark as
                # Low to appear in the Dojo
                if severity == "Informational":
                    return "Low"
                return severity
            else:
                if level == "Level 1":
                    criticality = "Critical"
                else:
                    criticality = "High"
        elif result == "MANUAL":
            criticality = "Medium"
        return criticality
