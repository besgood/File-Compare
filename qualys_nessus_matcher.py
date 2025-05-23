#!/usr/bin/env python3

import os
import time
import requests
import pandas as pd
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from getpass import getpass
from requests.auth import HTTPBasicAuth

# === Constants ===
QUALYS_BASE_URL = "https://qualysapi.qualys.com"
REPORTS_DIR = "reports"
OUTPUT_FORMAT = "csv"
HEADERS = {"X-Requested-With": "Python Script"}

# === Ensure reports directory exists ===
os.makedirs(REPORTS_DIR, exist_ok=True)

# === Get credentials and Nessus file info ===
username = input("Qualys Username: ")
password = getpass("Qualys Password: ")
nessus_file = input("Enter Nessus Excel filename: ").strip()
nessus_sheet = input("Enter Nessus sheet name: ").strip()

# === Host input selection ===
def build_host_input():
    option = input("Use asset group ID(s) (1) or host file (2)? Enter 1 or 2: ").strip()
    if option == "1":
        ag_ids = input("Enter Asset Group ID(s) comma-separated: ").strip()
        return "asset_group_ids", ag_ids
    elif option == "2":
        host_file = input("Enter host file path (one IP per line): ").strip()
        with open(host_file, "r") as f:
            ips = f.read().strip().replace("\n", ",").replace("\r", "")
        return "ips", ips
    else:
        raise ValueError("Invalid input.")

# === Launch Qualys Report ===
def launch_report():
    report_title = f"Qualys_Report_{int(time.time())}"
    template_id = input("Enter Qualys Report Template ID: ").strip()
    input_type, input_value = build_host_input()

    data = {
        "action": "launch",
        "report_title": report_title,
        "report_type": "Scan",
        "template_id": template_id,
        "output_format": OUTPUT_FORMAT,
        input_type: input_value
    }

    response = requests.post(
        f"{QUALYS_BASE_URL}/api/2.0/fo/report/",
        data=data,
        headers=HEADERS,
        auth=HTTPBasicAuth(username, password)
    )

    print("⏳ Waiting 10 seconds for report ID...")
    time.sleep(10)

    root = ET.fromstring(response.text)
    for item in root.findall(".//ITEM"):
        key = item.find("KEY")
        value = item.find("VALUE")
        if key is not None and key.text == "ID" and value is not None:
            return value.text, report_title

    raise Exception("Report ID not found.")

# === Check Report Status ===
def check_status(report_id):
    response = requests.get(
        f"{QUALYS_BASE_URL}/api/2.0/fo/report/",
        params={"action": "list", "id": report_id},
        headers=HEADERS,
        auth=HTTPBasicAuth(username, password)
    )
    root = ET.fromstring(response.text)
    state = root.find(".//STATE")
    return state.text if state is not None else "Unknown"

# === Download Report ===
def download_report(report_id, report_title):
    response = requests.get(
        f"{QUALYS_BASE_URL}/api/2.0/fo/report/",
        params={"action": "fetch", "id": report_id},
        headers=HEADERS,
        auth=HTTPBasicAuth(username, password)
    )
    filepath = os.path.join(REPORTS_DIR, f"{report_title}.csv")
    with open(filepath, "wb") as f:
        f.write(response.content)
    print(f"✅ Report downloaded to: {filepath}")
    return filepath

# === Match Nessus and Qualys Data ===
def match_findings(nessus_file, nessus_sheet, qualys_file):
    nessus = pd.read_excel(nessus_file, sheet_name=nessus_sheet)
    qualys = pd.read_csv(qualys_file, skiprows=4)

    nessus.columns = [col.strip() for col in nessus.columns]
    qualys.columns = [col.strip() for col in qualys.columns]

    nessus = nessus.rename(columns={
        "IP Address": "IP", "Port": "Port", "CVE": "CVEs", "Unique ID": "UniqueID"
    })
    qualys = qualys.rename(columns={
        "IP": "IP", "Port": "Port", "QID": "QID", "CVE ID": "CVEs", "Vulnerability State": "Vuln Status"
    })

    nessus["CVEs"] = nessus["CVEs"].astype(str).str.split(",")
    qualys["CVEs"] = qualys["CVEs"].astype(str).str.split(",")

    nessus = nessus.explode("CVEs")
    qualys = qualys.explode("CVEs")

    nessus["CVEs"] = nessus["CVEs"].str.strip()
    qualys["CVEs"] = qualys["CVEs"].str.strip()

    nessus["key"] = nessus["IP"].astype(str) + ":" + nessus["Port"].astype(str) + ":" + nessus["CVEs"]
    qualys["key"] = qualys["IP"].astype(str) + ":" + qualys["Port"].astype(str) + ":" + qualys["CVEs"]

    qualys_keys = set(qualys["key"])
    nessus["Match"] = nessus["key"].apply(lambda k: "Match" if k in qualys_keys else "No Match")

    match_summary = (
        nessus.merge(qualys[["key", "QID", "Vuln Status"]], on="key", how="left")
        .groupby(["UniqueID", "IP", "Port", "CVEs", "QID", "Vuln Status"])
        ["Match"].apply(lambda x: "Match" if "Match" in x.values else "No Match")
        .reset_index()
    )

    out_path = os.path.join(REPORTS_DIR, "nessus_vs_qualys_results.xlsx")
    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
        match_summary.to_excel(writer, index=False, sheet_name="Match Summary")
        nessus.to_excel(writer, index=False, sheet_name="Nessus Expanded")
        qualys.to_excel(writer, index=False, sheet_name="Qualys Expanded")

    print(f"📊 Match results saved to {out_path}")

# === Main Script ===
def main():
    mode = input("1 = New Report, 2 = Use Existing Report ID: ").strip()
    if mode == "1":
        report_id, report_title = launch_report()
    else:
        report_id = input("Enter existing Report ID: ").strip()
        report_title = f"Qualys_Report_{report_id}"

    while True:
        status = check_status(report_id)
        print(f"Report status: {status}")
        if status.lower() == "finished":
            file_path = download_report(report_id, report_title)
            break
        else:
            wait = datetime.now() + timedelta(minutes=10)
            print(f"⏱ Will retry at {wait.strftime('%H:%M:%S')}")
            time.sleep(600)

    match_findings(nessus_file, nessus_sheet, file_path)

if __name__ == "__main__":
    main()
