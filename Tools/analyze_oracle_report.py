#!python3

# Usage: ./Tools/analyze_oracle_report.py oracle_log.csv

import csv
import argparse
import sys

parser = argparse.ArgumentParser(description="Analye oracle report")
parser.add_argument("report", type=argparse.FileType("r"), default=sys.stdin)

args = parser.parse_args()

total_emails = 0
valid_emails = 0
no_signature_emails = 0
valid_insecure_emails = 0

reader = csv.DictReader(args.report)
for row in reader:
    total_emails += 1
    if "SUCCESS" in row["thunderbird"] and row["dkimpy"] == "signature ok" and "pass" in row["mailauth"] and "Valid" in row["dkimverifier"]:
        if "Valid" not in row["dkimverifier"].replace("Valid_Insecure", ""):
            valid_insecure_emails += 1
        else:
            valid_emails += 1
            continue
    if (
        row["dkimpy"] == "signature verification failed"
        and "message not signed" in row["mailauth"]
        and "NoSignature" in row["dkimverifier"]
    ):
        no_signature_emails += 1
        continue
    print(row["filename"][-19:], row["thunderbird"], row["dkimpy"], row["mailauth"], row["dkimverifier"])


print("total_emails: ", total_emails)
print("valid_emails: ", valid_emails)
print("valid_insecure_emails: ", valid_insecure_emails)
print("no_signature_emails: ", no_signature_emails)
print("fail_emails: ", total_emails - valid_emails - no_signature_emails - valid_insecure_emails)