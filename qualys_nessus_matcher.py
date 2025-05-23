#!/usr/bin/env python3

import pandas as pd
import os
import requests
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from getpass import getpass
from requests.auth import HTTPBasicAuth

# === Constants ===
QUALYS_BASE_URL = "https://qualysapi.qualys.com"
OUTPUT_FORMAT = "csv"
HEADERS = {"X-Requested-With": "Python Script"}
REPORTS_DIR = "reports"

# === Setup ===
os.makedirs(REPORTS_DIR, exist_ok=True)

# === User Inputs ===
nessus_file = input("Enter the filename of the Nessus Excel file (e.g., `nessus_findings.xlsx`): ").strip()
nessus_sheet = input("Enter the sheet name for Nessus findings (e.g., `Master`): ").strip()

USERNAME = input("Qualys Username: ")
PASSWORD = getpass("Qualys Password: ")

# === Qualys Report Functions ===

def build_host_input():
    option = input("Use asset group ID(s) (1) or host file (2)? Enter 1 or 2: ").strip()
    if option == "1":
        ag_ids = input("Enter one or more Asset Group IDs (comma-separated): ").strip()
        return "asset_group_ids", ag_ids
    elif option == "2":
        host_file = input("Enter path to host file (one IP per line): ").strip()
        try:
            with open(host_file, "r") as f:
                ips = f.read().strip().replace("\n", ",").replace("\r", "")
            return "ips", ips
        except Exception as e:
            raise Exception(f"Failed to read host file: {e}")
    else:
        raise ValueError("Invalid input. Choose 1 or 2.")

def launch_report():
    report_title = f"Qualys_Report_{int(time.time())}"
    template_id = input("Enter Report Template ID: ").strip()
    input_type, input_value = build_host_input()

    data = {
        "action": "launch",
        "report_title": report_title,
        "report_type": "Scan",
        "template_id": template_id,
        "output_format": OUTPUT_FORMAT,
        input_type: input_value
    }

    print("🚀 Launching report...")
    response = requests.post(
        f"{QUALYS_BASE_URL}/api/2.0/fo/report/",
        data=data,
        headers=HEADERS,
        auth=HTTPBasicAuth(USERNAME, PASSWORD)
    )

    print("⏳ Waiting 10 seconds to allow Qualys to generate the report ID...")
    wait_until = datetime.now() + timedelta(seconds=10)
    print(f"🕒 Will try again at: {wait_until.strftime('%Y-%m-%d %H:%M:%S')}")
    time.sleep(10)

    root = ET.fromstring(response.text)
    report_id = None
    for item in root.findall(".//ITEM"):
        key = item.find("KEY")
        value = item.find("VALUE")
        if key is not None and key.text == "ID" and value is not None:
            report_id = value.text
            break

    if not report_id:
        raise Exception(f"❌ Report ID not found in response:\n{response.text}")

    print(f"📄 Report launched with ID: {report_id}")
    return report_id, report_title

def check_report_status(report_id):
    response = requests.get(
        f"{QUALYS_BASE_URL}/api/2.0/fo/report/",
        params={"action": "list", "id": report_id},
        headers=HEADERS,
        auth=HTTPBasicAuth(USERNAME, PASSWORD)
    )

    root = ET.fromstring(response.text)
    state_elem = root.find(".//STATE")
    if state_elem is not None:
        return state_elem.text
    else:
        raise Exception(f"Could not determine status. Response:\n{response.text}")

def download_report(report_id, report_title):
    response = requests.get(
        f"{QUALYS_BASE_URL}/api/2.0/fo/report/",
        params={"action": "fetch", "id": report_id},
        headers=HEADERS,
        auth=HTTPBasicAuth(USERNAME, PASSWORD)
    )

    filename = os.path.join(REPORTS_DIR, f"{report_title}.csv")
    with open(filename, "wb") as f:
        f.write(response.content)
    print(f"✅ Report downloaded and saved as {filename}")
    return filename

# === Main Execution ===

print("=== Qualys Report Generation ===")
choice = input("Enter 1 to launch a new report or 2 to check/download existing report: ").strip()
if choice == "1":
    report_id, report_title = launch_report()
elif choice == "2":
    report_id = input("Enter existing Report ID: ").strip()
    report_title = f"Qualys_Report_{report_id}"
else:
    print("Invalid choice.")
    exit()

while True:
    try:
        status = check_report_status(report_id)
        print(f"📊 Report status: {status}")
        if status.lower() == "finished":
            qualys_csv = download_report(report_id, report_title)
            break
        else:
            next_try = datetime.now() + timedelta(minutes=10)
            print(f"⏱ Waiting 10 minutes. Will try again at {next_try.strftime('%Y-%m-%d %H:%M:%S')}")
            time.sleep(600)
    except Exception as e:
        print(f"⚠️ Error: {e}")
        exit()

print("=== Matching Nessus to Qualys ===")

nessus_df = pd.read_excel(nessus_file, sheet_name=nessus_sheet)
qualys_df = pd.read_csv(qualys_csv)

# Normalize column names
nessus_df.columns = nessus_df.columns.str.strip()
qualys_df.columns = qualys_df.columns.str.strip()

# Use user-defined or auto-detected columns
nessus_ip_col = "IP"
nessus_port_col = "Port"
nessus_cve_col = "CVEs"

qualys_ip_col = "IP"
qualys_port_col = "Port"
qualys_qid_col = "QID"
qualys_cve_col = "CVE ID"
qualys_vuln_state_col = "Status"
qualys_uuid_col = "UUID"

# Explode CVEs
nessus_df[nessus_cve_col] = nessus_df[nessus_cve_col].astype(str).str.split(",")
qualys_df[qualys_cve_col] = qualys_df[qualys_cve_col].astype(str).str.split(",")

nessus_exploded = nessus_df.explode(nessus_cve_col)
qualys_exploded = qualys_df.explode(qualys_cve_col)

nessus_exploded[nessus_cve_col] = nessus_exploded[nessus_cve_col].str.strip()
qualys_exploded[qualys_cve_col] = qualys_exploded[qualys_cve_col].str.strip()

nessus_exploded["key"] = (
    nessus_exploded[nessus_ip_col].astype(str) + ":" +
    nessus_exploded[nessus_port_col].astype(str) + ":" +
    nessus_exploded[nessus_cve_col]
)
qualys_exploded["key"] = (
    qualys_exploded[qualys_ip_col].astype(str) + ":" +
    qualys_exploded[qualys_port_col].astype(str) + ":" +
    qualys_exploded[qualys_cve_col]
)

qualys_keys = set(qualys_exploded["key"])
nessus_exploded["Match"] = nessus_exploded["key"].apply(
    lambda k: "Match" if k in qualys_keys else "No Match"
)

result_df = (
    nessus_exploded
    .merge(qualys_exploded[[ "key", qualys_qid_col, qualys_vuln_state_col, qualys_uuid_col ]], on="key", how="left")
    .rename(columns={
        qualys_qid_col: "QID",
        qualys_vuln_state_col: "Vuln State",
        qualys_uuid_col: "UniqueID",
        nessus_ip_col: "IP",
        nessus_port_col: "Port",
        nessus_cve_col: "CVE"
    })
)

result_df = result_df[["UniqueID", "IP", "Port", "CVE", "Vuln State", "QID", "Match"]]

output_excel = os.path.join(REPORTS_DIR, "nessus_vs_qualys_results.xlsx")
with pd.ExcelWriter(output_excel, engine="openpyxl") as writer:
    result_df.to_excel(writer, index=False, sheet_name="Match Results")
    nessus_df.to_excel(writer, index=False, sheet_name="Nessus Original")
    qualys_df.to_excel(writer, index=False, sheet_name="Qualys Original")

print(f"✅ Results saved to {output_excel}")
