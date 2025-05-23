#!/usr/bin/env python3
"""
Unified script to:
1. Launch and download a Qualys report.
2. Cross-reference it with Nessus data.
"""

import os
import time
import pandas as pd
import requests
import xml.etree.ElementTree as ET
from getpass import getpass
from datetime import datetime

# === Qualys Report Downloader ===
def download_qualys_report_interactive():
    username = input("Qualys Username: ").strip()
    password = getpass("Qualys Password: ").strip()

    print("\nChoose input method:")
    print("1. Asset Group ID(s)")
    print("2. Host file (host.txt with IPs)")

    choice = input("Enter choice (1 or 2): ").strip()
    asset_group_ids = []
    ips = ""

    if choice == "1":
        asset_group_ids = input("Enter comma-separated Asset Group IDs: ").split(",")
        use_ips = False
    else:
        with open("host.txt", "r") as f:
            ips = ",".join([line.strip() for line in f if line.strip()])
        use_ips = True

    template_id = input("Enter Report Template ID: ").strip()
    report_title = f"PCI_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    headers = {
        "X-Requested-With": "Python script"
    }
    url = "https://qualysapi.qualys.com/api/2.0/fo/report/"

    data = {
        "action": "launch",
        "report_type": "Scan",
        "template_id": template_id,
        "output_format": "csv",
        "report_title": report_title,
        "ips": ips if use_ips else None,
        "asset_group_ids": ",".join(asset_group_ids) if not use_ips else None
    }
    # Remove None values
    data = {k: v for k, v in data.items() if v is not None}

    print("Launching report...")
    response = requests.post(url, headers=headers, data=data, auth=(username, password))

    time.sleep(10)  # Wait for report ID generation

    if response.status_code != 200:
        raise Exception(f"Error launching report: {response.text}")

    root = ET.fromstring(response.text)
    report_id = None
    for item in root.findall(".//ITEM"):
        key = item.find("KEY")
        value = item.find("VALUE")
        if key is not None and key.text == "ID" and value is not None:
            report_id = value.text
            break

    if not report_id:
        raise Exception("Report ID not found in response.")

    print(f"Report launched with ID: {report_id}")

    # Wait for completion
    status = ""
    while status != "Finished":
        time.sleep(600)  # 10 minutes
        status_check = requests.get(
            f"{url}?action=list&id={report_id}",
            headers=headers,
            auth=(username, password)
        )
        root = ET.fromstring(status_check.text)
        state = root.find(".//STATE")
        status = state.text if state is not None else ""
        if status != "Finished":
            print(f"Report status: {status} — Will try again at {datetime.now().strftime('%H:%M:%S')}")

    print("Report is ready. Downloading...")

    # Download report
    download_url = f"{url}?action=fetch&id={report_id}"
    download_response = requests.get(download_url, headers=headers, auth=(username, password))

    if download_response.status_code != 200:
        raise Exception("Failed to download report.")

    os.makedirs("reports", exist_ok=True)
    filename = f"reports/qualys_report_{report_id}.csv"
    with open(filename, "wb") as f:
        f.write(download_response.content)

    print(f"✅ Report saved to {filename}")
    return filename


# === Nessus vs Qualys Matcher ===
def perform_matching(nessus_file, nessus_sheet, qualys_file):
    nessus = pd.read_excel(nessus_file, sheet_name=nessus_sheet, header=0)
    qualys = pd.read_csv(qualys_file)

    # Auto-detect columns
    nessus_ip_col = next((col for col in nessus.columns if "ip" in col.lower()), "IP")
    nessus_port_col = next((col for col in nessus.columns if "port" in col.lower()), "Port")
    nessus_cve_col = next((col for col in nessus.columns if "cve" in col.lower()), "CVEs")

    qualys_ip_col = next((col for col in qualys.columns if "ip" in col.lower()), "IP")
    qualys_port_col = next((col for col in qualys.columns if "port" in col.lower()), "Port")
    qualys_qid_col = next((col for col in qualys.columns if "qid" in col.lower()), "QID")
    qualys_cve_col = next((col for col in qualys.columns if "cve" in col.lower()), "CVEs")
    qualys_state_col = next((col for col in qualys.columns if "vuln" in col.lower()), "Vuln State")

    # Rename for consistency
    nessus = nessus.rename(columns={
        nessus_ip_col: "IP",
        nessus_port_col: "Port",
        nessus_cve_col: "CVEs"
    })

    qualys = qualys.rename(columns={
        qualys_ip_col: "IP",
        qualys_port_col: "Port",
        qualys_qid_col: "QID",
        qualys_cve_col: "CVEs",
        qualys_state_col: "Vuln State"
    })

    nessus = nessus[["IP", "Port", "CVEs"]].dropna()
    qualys = qualys[["IP", "Port", "QID", "CVEs", "Vuln State"]].dropna()

    nessus["CVEs"] = nessus["CVEs"].astype(str).str.split(",")
    qualys["CVEs"] = qualys["CVEs"].astype(str).str.split(",")

    nessus_exploded = nessus.explode("CVEs")
    qualys_exploded = qualys.explode("CVEs")

    nessus_exploded["CVEs"] = nessus_exploded["CVEs"].str.strip()
    qualys_exploded["CVEs"] = qualys_exploded["CVEs"].str.strip()

    nessus_exploded["key"] = (
        nessus_exploded["IP"].astype(str) + ":" +
        nessus_exploded["Port"].astype(str) + ":" +
        nessus_exploded["CVEs"]
    )

    qualys_exploded["key"] = (
        qualys_exploded["IP"].astype(str) + ":" +
        qualys_exploded["Port"].astype(str) + ":" +
        qualys_exploded["CVEs"]
    )

    qualys_keys = set(qualys_exploded["key"])
    nessus_exploded["Match"] = nessus_exploded["key"].apply(
        lambda k: "Match" if k in qualys_keys else "No Match"
    )

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

    os.makedirs("reports", exist_ok=True)
    output_path = "reports/nessus_vs_qualys_results.xlsx"
    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        nessus_result.to_excel(writer, index=False, sheet_name="Nessus Match Results")
        nessus.to_excel(writer, index=False, sheet_name="Master (Original)")
        qualys.to_excel(writer, index=False, sheet_name="Qualys (Original)")

    print(f"✅ Match results saved to: {output_path}")


# === Main ===
def main():
    nessus_file = input("Enter path to Nessus findings Excel file: ").strip()
    nessus_sheet = input("Enter sheet name containing Nessus findings: ").strip()

    qualys_report_path = download_qualys_report_interactive()

    perform_matching(
        nessus_file=nessus_file,
        nessus_sheet=nessus_sheet,
        qualys_file=qualys_report_path
    )


if __name__ == "__main__":
    main()
