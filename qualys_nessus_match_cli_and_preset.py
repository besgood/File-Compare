
import argparse
import json
import os


def load_config(config_path):
    if not config_path or not os.path.exists(config_path):
        return {}
    with open(config_path, "r") as f:
        return json.load(f)

def get_value(config, cli_value, key, prompt_msg, df=None):
    if cli_value:
        return cli_value
    elif key in config:
        return config[key]
    elif df is not None:
        print(f"⚠️  Could not find {key} in CLI or config.")
        return prompt_user_for_column(df, prompt_msg)
    else:
        return input(f"{prompt_msg}: ")

def parse_args():
    parser = argparse.ArgumentParser(description="Compare Nessus and Qualys scan data.")
    parser.add_argument("--nessus-file", help="Path to Nessus xlsx file")
    parser.add_argument("--qualys-file", help="Path to Qualys xlsx file")
    parser.add_argument("--nessus-sheet", help="Sheet name for Nessus findings")
    parser.add_argument("--qualys-sheet", help="Sheet name for Qualys findings")
    parser.add_argument("--config", help="Path to JSON config file")
    parser.add_argument("--output-dir", default="reports", help="Directory to save the output file")
    return parser.parse_args()

#!/usr/bin/env python3


import os
os.makedirs("reports", exist_ok=True)

import requests
import time
import os
import xml.etree.ElementTree as ET
import pandas as pd
from datetime import datetime, timedelta
from getpass import getpass
from requests.auth import HTTPBasicAuth

# Constants
QUALYS_BASE_URL = "https://qualysapi.qualys.com"
OUTPUT_FORMAT = "csv"
HEADERS = {"X-Requested-With": "Python Script"}
REPORTS_DIR = "reports"

# Ensure reports directory exists
os.makedirs(REPORTS_DIR, exist_ok=True)

# Get Nessus findings file (Excel)
NESSUS_FILE = input("Enter the path to the Nessus findings Excel file for cross-reference: ").strip()

# Get Nessus findings file (Excel)
NESSUS_FILE = input("Enter the path to the Nessus findings Excel file for cross-reference: ").strip()
NESSUS_SHEET = input("Enter the sheet name within the Nessus Excel file containing the findings: ").strip()

# Get user credentials
USERNAME = input("Qualys Username: ")
PASSWORD = getpass("Qualys Password: ")

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

def process_csv_to_excel(csv_path, excel_path):
    try:
        df = pd.read_csv(csv_path)
        df_filtered = df[['IP', 'Port', 'QID', 'CVE ID', 'Vulnerability Status']]
        df_filtered.columns = ['IP', 'Port', 'QID', 'CVEs', 'Vuln State']
        df_filtered.to_excel(excel_path, index=False)
        print(f"📊 Converted CSV to Excel: {excel_path}")
    except Exception as e:
        print(f"⚠️ Failed to convert CSV to Excel: {e}")

def download_report(report_id, report_title):
    response = requests.get(
        f"{QUALYS_BASE_URL}/api/2.0/fo/report/",
        params={"action": "fetch", "id": report_id},
        headers=HEADERS,
        auth=HTTPBasicAuth(USERNAME, PASSWORD)
    )

    csv_filename = os.path.join(REPORTS_DIR, f"{report_title}.csv")
    with open(csv_filename, "wb") as f:
        f.write(response.content)
    print(f"✅ Report downloaded as CSV: {csv_filename}")

    excel_filename = os.path.join(REPORTS_DIR, f"{report_title}.xlsx")
    process_csv_to_excel(csv_filename, excel_filename)

def main():
    choice = input("Enter 1 to launch a new report or 2 to check/download existing report: ").strip()
    if choice == "1":
        report_id, report_title = launch_report()
    elif choice == "2":
        report_id = input("Enter existing Report ID: ").strip()
        report_title = f"Qualys_Report_{report_id}"
    else:
        print("Invalid choice.")
        return

    while True:
        try:
            status = check_report_status(report_id)
            print(f"📊 Report status: {status}")
            if status.lower() == "finished":
                download_report(report_id, report_title)
                break
            else:
                next_try = datetime.now() + timedelta(minutes=10)
                print(f"⏱ Waiting 10 minutes. Will try again at {next_try.strftime('%Y-%m-%d %H:%M:%S')}")
                time.sleep(600)
        except Exception as e:
            print(f"⚠️ Error: {e}")
            break

if __name__ == "__main__":
    main()


# === Match Nessus and Qualys Data ===
import pandas as pd

# Load Nessus findings and sheet
nessus = pd.read_excel(NESSUS_FILE, sheet_name=NESSUS_SHEET, header=0)
qualys = pd.read_csv(qualys_csv_file)

# === Column Detection ===
def detect_column(df, possible_names):
    for name in df.columns:
        for target in possible_names:
            if target.lower() in str(name).lower():
                return name
    return None

# Detect Nessus columns
nessus_ip_col = detect_column(nessus, ["ip", "host"])
nessus_port_col = detect_column(nessus, ["port"])
nessus_cve_col = detect_column(nessus, ["cve", "cves", "cve id"])

if not nessus_ip_col or not nessus_port_col or not nessus_cve_col:
    print("❌ Could not detect required columns in Nessus sheet.")
    print("Please check that the sheet contains IP, Port, and CVE columns.")
    exit(1)

def prompt_user_for_column(df, label):
    print(f"Available columns for {label}:")
    for i, col in enumerate(df.columns):
        print(f"{i}: {col}")
    while True:
        try:
            idx = int(input(f"Enter the column number to use for {label}: "))
            if 0 <= idx < len(df.columns):
                return df.columns[idx]
            else:
                print("Invalid number. Try again.")
        except ValueError:
            print("Please enter a valid number.")

def get_column(df, label, options):
    col = detect_column(df, options)
    if not col:
        print(f"⚠️ Could not automatically detect the column for {label}.")
        col = prompt_user_for_column(df, label)
    return col

# Get columns for Nessus
nessus_ip_col = get_column(nessus, "Nessus IP", ["ip", "host"])
nessus_port_col = get_column(nessus, "Nessus Port", ["port"])
nessus_cve_col = get_column(nessus, "Nessus CVEs", ["cve", "cves", "cve id"])

nessus = nessus[[nessus_ip_col, nessus_port_col, nessus_cve_col]].dropna()
nessus.columns = ["IP", "Port", "CVEs"]

# Get columns for Qualys
qualys_ip_col = get_column(qualys, "Qualys IP", ["ip", "host"])
qualys_port_col = get_column(qualys, "Qualys Port", ["port"])
qualys_qid_col = get_column(qualys, "Qualys QID", ["qid"])
qualys_cve_col = get_column(qualys, "Qualys CVEs", ["cve", "cves", "cve id"])
qualys_state_col = get_column(qualys, "Qualys Vuln State", ["vuln state", "status"])

qualys = qualys[[qualys_ip_col, qualys_port_col, qualys_qid_col, qualys_cve_col, qualys_state_col]].dropna()
qualys.columns = ["IP", "Port", "QID", "CVEs", "Vuln State"]
nessus.columns = ["IP", "Port", "CVEs"]

# Detect Qualys columns
qualys_ip_col = detect_column(qualys, ["ip", "host"])
qualys_port_col = detect_column(qualys, ["port"])
qualys_qid_col = detect_column(qualys, ["qid"])
qualys_cve_col = detect_column(qualys, ["cve", "cves", "cve id"])
qualys_state_col = detect_column(qualys, ["vuln state", "status"])

if not all([qualys_ip_col, qualys_port_col, qualys_qid_col, qualys_cve_col, qualys_state_col]):
    print("❌ Could not detect required columns in Qualys sheet.")
    print("Please ensure columns for IP, Port, QID, CVEs, and Vuln State are present.")
    exit(1)

qualys = qualys[[qualys_ip_col, qualys_port_col, qualys_qid_col, qualys_cve_col, qualys_state_col]].dropna()
qualys.columns = ["IP", "Port", "QID", "CVEs", "Vuln State"]      # Column R
nessus.columns.values[18] = "Port"    # Column S
nessus.columns.values[29] = "CVEs"    # Column AD

# (Qualys column renaming handled by detection logic)      # Column B
qualys.columns.values[11] = "Port"    # Column L
qualys.columns.values[5]  = "QID"     # Column F
qualys.columns.values[15] = "CVEs"    # Column P
qualys.columns.values[8]  = "Vuln State"  # Column I

nessus = nessus[["IP", "Port", "CVEs"]].dropna()
qualys = qualys[["IP", "Port", "QID", "CVEs", "Vuln State"]].dropna()

nessus["CVEs"] = nessus["CVEs"].astype(str).str.split(",")
qualys["CVEs"] = qualys["CVEs"].astype(str).str.split(",")

nessus_exploded = nessus.explode("CVEs")
qualys_exploded = qualys.explode("CVEs")

nessus_exploded["CVEs"] = nessus_exploded["CVEs"].str.strip()
qualys_exploded["CVEs"] = qualys_exploded["CVEs"].str.strip()

nessus_exploded["key"] = nessus_exploded["IP"].astype(str) + ":" + nessus_exploded["Port"].astype(str) + ":" + nessus_exploded["CVEs"]
qualys_exploded["key"] = qualys_exploded["IP"].astype(str) + ":" + qualys_exploded["Port"].astype(str) + ":" + qualys_exploded["CVEs"]

qualys_keys = set(qualys_exploded["key"])
nessus_exploded["Match"] = nessus_exploded["key"].apply(lambda k: "Match" if k in qualys_keys else "No Match")

match_summary = (
    nessus_exploded
    .merge(qualys_exploded[["key", "QID", "Vuln State"]], on="key", how="left")
    .groupby(["IP", "Port", "QID", "Vuln State"])["Match"]
    .apply(lambda x: "Match" if "Match" in x.values else "No Match")
    .reset_index()
)

nessus_result = pd.merge(
    nessus.drop(columns=["CVEs"]),
    match_summary,
    on=["IP", "Port"],
    how="left"
)

with pd.ExcelWriter(os.path.join("reports", "nessus_vs_qualys_results.xlsx"), engine="openpyxl") as writer:
    nessus_result.to_excel(writer, index=False, sheet_name="Nessus Match Results")
    nessus.to_excel(writer, index=False, sheet_name="Master (Original)")
    qualys.to_excel(writer, index=False, sheet_name="Qualys (Original)")

print("✅ Nessus-Qualys match results saved to nessus_vs_qualys_results.xlsx")
