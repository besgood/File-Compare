#!/usr/bin/env python3

import pandas as pd
import requests
import time
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from getpass import getpass
from requests.auth import HTTPBasicAuth

# Constants
QUALYS_BASE_URL = "https://qualysapi.qualys.com"
OUTPUT_FORMAT = "csv"
HEADERS = {"X-Requested-With": "Python Script"}
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# Get user credentials
USERNAME = input("Qualys Username: ")
PASSWORD = getpass("Qualys Password: ")

# === Load Qualys CSV with correct header handling ===
def load_qualys_csv(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    header_index = next(i for i, line in enumerate(lines) if line.strip().startswith('"IP","NetBIOS","DNS"'))
    return pd.read_csv(filepath, skiprows=header_index, quotechar='"', encoding='utf-8')

# === Launch and download Qualys report ===
def build_host_input():
    option = input("Use asset group ID(s) (1) or host file (2)? Enter 1 or 2: ").strip()
    if option == "1":
        ag_ids = input("Enter one or more Asset Group IDs (comma-separated): ").strip()
        return "asset_group_ids", ag_ids
    elif option == "2":
        host_file = input("Enter path to host file (one IP per line): ").strip()
        with open(host_file, "r") as f:
            ips = f.read().strip().replace("\n", ",").replace("\r", "")
        return "ips", ips
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
    response = requests.post(f"{QUALYS_BASE_URL}/api/2.0/fo/report/", data=data, headers=HEADERS, auth=HTTPBasicAuth(USERNAME, PASSWORD))
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
    response = requests.get(f"{QUALYS_BASE_URL}/api/2.0/fo/report/", params={"action": "list", "id": report_id}, headers=HEADERS, auth=HTTPBasicAuth(USERNAME, PASSWORD))
    root = ET.fromstring(response.text)
    state_elem = root.find(".//STATE")
    if state_elem is not None:
        return state_elem.text
    else:
        raise Exception(f"Could not determine status. Response:\n{response.text}")

def download_report(report_id, report_title):
    response = requests.get(f"{QUALYS_BASE_URL}/api/2.0/fo/report/", params={"action": "fetch", "id": report_id}, headers=HEADERS, auth=HTTPBasicAuth(USERNAME, PASSWORD))
    filename = os.path.join(REPORTS_DIR, f"{report_title}.csv")
    with open(filename, "wb") as f:
        f.write(response.content)
    print(f"✅ Report downloaded and saved as {filename}")
    return filename

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
                csv_path = download_report(report_id, report_title)
                qualys_df = load_qualys_csv(csv_path)
                print("🔍 Qualys report successfully loaded:")
                print(qualys_df.head())
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
