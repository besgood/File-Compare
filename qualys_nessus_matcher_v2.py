#!/usr/bin/env python3

import os
import time
import requests
import pandas as pd
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from getpass import getpass
from requests.auth import HTTPBasicAuth
from tqdm.auto import tqdm # Added for progress bars

# Initialize tqdm for pandas
tqdm.pandas()

# === Constants ===
QUALYS_BASE_URL = "https://qualysapi.qualys.com"
REPORTS_DIR = "reports"
OUTPUT_FORMAT = "csv"
HEADERS = {"X-Requested-With": "Python Script"}
MAX_ROWS_PER_FILE = 1048500 # Max rows per Excel sheet/file (slightly less than actual max for safety)


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

    print("🚀 Launching Qualys report...")
    response = requests.post(
        f"{QUALYS_BASE_URL}/api/2.0/fo/report/",
        data=data,
        headers=HEADERS,
        auth=HTTPBasicAuth(username, password)
    )

    print("⏳ Waiting 10 seconds for report ID to be available in API listing...")
    time.sleep(10) # Original wait time preserved

    root = ET.fromstring(response.text)
    # Check for successful launch response
    response_code_node = root.find(".//SIMPLE_RETURN/RESPONSE_CODE")
    if response_code_node is not None and response_code_node.text == "SUCCESS":
        print("✅ Report launch successful.")
    else:
        error_text = root.find(".//SIMPLE_RETURN/TEXT")
        print(f"⚠️ Report launch may have failed or ID not immediately available. API Response: {response.text if error_text is None else error_text.text}")
        # Even if not "SUCCESS", try to find ID as some APIs return it anyway.

    for item in root.findall(".//ITEM"):
        key = item.find("KEY")
        value = item.find("VALUE")
        if key is not None and key.text == "ID" and value is not None:
            print(f"Found Report ID: {value.text}")
            return value.text, report_title

    raise Exception(f"Report ID not found in launch response. API Response: {response.text}")

# === Check Report Status ===
def check_status(report_id):
    response = requests.get(
        f"{QUALYS_BASE_URL}/api/2.0/fo/report/",
        params={"action": "list", "id": report_id},
        headers=HEADERS,
        auth=HTTPBasicAuth(username, password)
    )
    response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
    root = ET.fromstring(response.text)
    state = root.find(".//REPORT/STATUS/STATE") # Path to state in report list
    return state.text if state is not None else "Unknown"

# === Download Report ===
def download_report(report_id, report_title):
    print(f"⬇️ Attempting to download report ID: {report_id}")
    response = requests.get(
        f"{QUALYS_BASE_URL}/api/2.0/fo/report/",
        params={"action": "fetch", "id": report_id},
        headers=HEADERS,
        auth=HTTPBasicAuth(username, password)
    )
    response.raise_for_status() # Ensure download was successful
    
    filepath = os.path.join(REPORTS_DIR, f"{report_title}.{OUTPUT_FORMAT.lower()}") # Use OUTPUT_FORMAT for extension
    with open(filepath, "wb") as f:
        f.write(response.content)
    print(f"✅ Report downloaded to: {filepath}")
    return filepath

# === Helper function to write DataFrames to Excel in chunks ===
def write_dataframe_to_excel_chunks(writer, df, sheet_name, main_writer_status, current_file_index_ref, base_output_filename_no_ext, ext):
    """
    Writes a large DataFrame to one or more Excel files, chunked by MAX_ROWS_PER_FILE.
    'writer' is the initial pandas ExcelWriter object.
    'main_writer_status' is a dict {'closed': Boolean, 'path': String} tracking the initial writer.
    'current_file_index_ref' is a list [int] to track part numbers across calls.
    """
    num_rows = len(df)
    if num_rows == 0:
        tqdm.write(f"Sheet '{sheet_name}' has no data. Attempting to write an empty sheet.")
        if writer and not main_writer_status['closed']: # Relies on our managed status
            try:
                pd.DataFrame().to_excel(writer, sheet_name=sheet_name, index=False)
                tqdm.write(f"Empty sheet '{sheet_name}' written to: {main_writer_status['path']}")
            except Exception as e:
                tqdm.write(f"Error writing empty sheet '{sheet_name}' to {main_writer_status['path']}: {e}")
        else:
            tqdm.write(f"Main writer for '{sheet_name}' is not available or closed, and sheet is empty. Skipping file creation for empty sheet.")
        return

    first_chunk_df = df.iloc[:MAX_ROWS_PER_FILE]
    
    wrote_first_chunk_to_initial_writer = False
    # Try to write the first chunk to the initial writer if our status says it's open
    if writer and not main_writer_status['closed']:
        try:
            tqdm.write(f"Writing first chunk of '{sheet_name}' ({len(first_chunk_df)} rows) to: {main_writer_status['path']}")
            first_chunk_df.to_excel(writer, sheet_name=sheet_name, index=False)
            wrote_first_chunk_to_initial_writer = True
        except Exception as e:
            tqdm.write(f"Error writing first chunk of '{sheet_name}' to {main_writer_status['path']}: {e}. Will attempt new file.")
            # If writing to main writer fails, ensure it's marked as closed for subsequent use by this function call
            main_writer_status['closed'] = True 

    if not wrote_first_chunk_to_initial_writer:
        # Initial writer was not available/usable, or writing failed. Create a new file for the first chunk.
        current_file_index_ref[0] += 1
        output_filename_part = f"{base_output_filename_no_ext}_part{current_file_index_ref[0]}{ext}"
        tqdm.write(f"Writing first chunk of '{sheet_name}' ({len(first_chunk_df)} rows) to new file: {output_filename_part}")
        with pd.ExcelWriter(output_filename_part, engine='openpyxl') as chunk_writer:
            first_chunk_df.to_excel(chunk_writer, sheet_name=sheet_name, index=False)
        
        # If the initial writer existed but wasn't used for this first chunk (or failed),
        # and our status still thought it was open, we should close it now.
        if writer and not main_writer_status['closed']:
            tqdm.write(f"Closing initial writer {main_writer_status['path']} as '{sheet_name}' (or its first chunk) is moved to new files.")
            try:
                writer.close()
            except Exception as e: 
                tqdm.write(f"Note: Error closing initial writer (it might have been closed due to prior error): {e}")
            main_writer_status['closed'] = True


    # Handle subsequent chunks, which always go to new files
    num_total_chunks = (num_rows + MAX_ROWS_PER_FILE - 1) // MAX_ROWS_PER_FILE
    for i in range(1, num_total_chunks): # Start from the second chunk (index 1)
        start_row = i * MAX_ROWS_PER_FILE
        end_row = min((i + 1) * MAX_ROWS_PER_FILE, num_rows)
        chunk_df = df.iloc[start_row:end_row]

        if chunk_df.empty:
            continue

        # If the first chunk went into the initial writer, and now we are making a new file for subsequent chunks,
        # close the initial writer if our status says it's still open.
        if writer and not main_writer_status['closed'] and wrote_first_chunk_to_initial_writer:
            tqdm.write(f"Closing initial writer {main_writer_status['path']} before creating new file for chunk {i+1} of '{sheet_name}'.")
            try:
                writer.close()
            except Exception as e:
                tqdm.write(f"Note: Error closing initial writer (it might have been closed due to prior error): {e}")
            main_writer_status['closed'] = True # Mark as closed globally

        current_file_index_ref[0] += 1
        output_filename_part = f"{base_output_filename_no_ext}_part{current_file_index_ref[0]}{ext}"
        tqdm.write(f"Writing chunk {i+1} of '{sheet_name}' ({len(chunk_df)} rows) to new file: {output_filename_part}")
        with pd.ExcelWriter(output_filename_part, engine='openpyxl') as chunk_writer:
            chunk_df.to_excel(chunk_writer, sheet_name=sheet_name, index=False)


# === Match Nessus and Qualys Data ===
def match_findings(nessus_file, nessus_sheet, qualys_file):
    print("🔄 Reading Nessus Excel file...")
    nessus = pd.read_excel(nessus_file, sheet_name=nessus_sheet)
    print("🔄 Reading Qualys CSV file...")
    try:
        qualys = pd.read_csv(qualys_file, skiprows=4, low_memory=False) 
    except pd.errors.EmptyDataError:
        print(f"⚠️ Qualys file '{qualys_file}' is empty or unreadable after skipping rows. Cannot proceed with matching.")
        return
    except Exception as e:
        print(f"⚠️ Error reading Qualys file '{qualys_file}': {e}. Cannot proceed with matching.")
        return

    print("🔄 Cleaning column names...")
    nessus.columns = [str(col).strip() for col in nessus.columns] 
    qualys.columns = [str(col).strip() for col in qualys.columns]

    print("🔄 Standardizing column names for Nessus...")
    nessus = nessus.rename(columns={
        "Reported Finding": "Reported Finding", 
        "IP Address": "IP", "Port": "Port", "CVE": "CVEs", "Unique ID": "UniqueID"
    })
    print("🔄 Standardizing column names for Qualys...")
    qualys = qualys.rename(columns={
        "IP": "IP", "Port": "Port", "QID": "QID", "CVE ID": "CVEs", "Vulnerability State": "Vuln Status"
    })

    required_nessus_cols = ["IP", "Port", "CVEs", "UniqueID", "Reported Finding"]
    required_qualys_cols = ["IP", "Port", "CVEs", "QID", "Vuln Status"]

    for col in required_nessus_cols:
        if col not in nessus.columns:
            raise KeyError(f"Nessus DataFrame missing required column after rename: '{col}'. Available: {list(nessus.columns)}")
    for col in required_qualys_cols:
        if col not in qualys.columns:
            raise KeyError(f"Qualys DataFrame missing required column after rename: '{col}'. Available: {list(qualys.columns)}")

    print("🔄 Processing CVEs (splitting and exploding)...")
    nessus["CVEs"] = nessus["CVEs"].fillna('').astype(str).str.split(",")
    qualys["CVEs"] = qualys["CVEs"].fillna('').astype(str).str.split(",")

    print("   Exploding Nessus CVEs...")
    nessus = nessus.explode("CVEs")
    print("   Exploding Qualys CVEs...")
    qualys = qualys.explode("CVEs")

    nessus["CVEs"] = nessus["CVEs"].str.strip()
    qualys["CVEs"] = qualys["CVEs"].str.strip()

    print("🔄 Creating merge keys...")
    nessus["key"] = nessus["IP"].astype(str) + ":" + nessus["Port"].astype(str) + ":" + nessus["CVEs"].astype(str)
    qualys["key"] = qualys["IP"].astype(str) + ":" + qualys["Port"].astype(str) + ":" + qualys["CVEs"].astype(str)

    qualys_keys = set(qualys["key"])
    print("🔄 Applying match logic to Nessus data...")
    nessus["Match"] = nessus["key"].progress_apply(lambda k: "Match" if k in qualys_keys else "No Match")

    print("🔄 Generating match summary...")
    match_summary = (
        nessus.merge(qualys[["key", "QID", "Vuln Status"]], on="key", how="left")
        .groupby(["UniqueID", "IP", "Port", "Reported Finding", "CVEs", "QID", "Vuln Status"], dropna=False) 
        .progress_apply(lambda x: pd.Series({"Match": "Match" if "Match" in x["Match"].values else "No Match"})) 
        .reset_index()
    )
    
    out_path_base_name = "nessus_vs_qualys_results"
    out_path_base_dir = os.path.join(REPORTS_DIR, out_path_base_name)
    out_ext = ".xlsx"

    file_part_counter = [0]  
    initial_output_filename = f"{out_path_base_dir}{out_ext}" 

    if not match_summary.empty and len(match_summary) > MAX_ROWS_PER_FILE:
        file_part_counter[0] = 1
        initial_output_filename = f"{out_path_base_dir}_part{file_part_counter[0]}{out_ext}"
        tqdm.write(f"First sheet ('Match Summary') is large. Initial output file will be: {initial_output_filename}")
    
    main_excel_writer = None
    main_writer_status = {'closed': True, 'path': None} # Start as closed, update when opened

    try:
        tqdm.write(f"Creating initial Excel file: {initial_output_filename}")
        main_excel_writer = pd.ExcelWriter(initial_output_filename, engine="openpyxl")
        main_writer_status['closed'] = False # Mark as open
        main_writer_status['path'] = initial_output_filename
    except Exception as e:
        tqdm.write(f"Error creating initial Excel writer for {initial_output_filename}: {e}")
        print(f"📊 Match results could not be saved due to Excel writer error.")
        return 

    sheets_to_write_info = [
        ("Match Summary", match_summary),
        ("Nessus Expanded", nessus), 
        ("Qualys Expanded", qualys)  
    ]

    tqdm.write("Writing data to Excel sheets...")
    for sheet_name, df_to_write in tqdm(sheets_to_write_info, desc="Processing sheets"):
        current_writer_for_this_sheet = main_excel_writer # Pass the writer object
        
        write_dataframe_to_excel_chunks(
            current_writer_for_this_sheet, # Pass the writer object
            df_to_write,
            sheet_name,
            main_writer_status, 
            file_part_counter,  
            out_path_base_dir,  
            out_ext
        )

    # Final close of the main writer if our status says it's still open
    if main_excel_writer and not main_writer_status['closed']:
        tqdm.write(f"Closing the initial Excel file: {main_writer_status['path']}")
        try:
            main_excel_writer.close()
            main_writer_status['closed'] = True # Explicitly mark as closed after successful close
        except Exception as e:
            tqdm.write(f"Error during final close of main Excel writer {main_writer_status['path']}: {e}")
    elif main_excel_writer and main_writer_status['closed']: # If our status already says closed
        tqdm.write(f"Initial Excel writer ({main_writer_status.get('path', 'N/A')}) was already considered closed or handled by chunking.")

    print(f"📊 Match results processing complete.")
    if file_part_counter[0] == 0: 
        print(f"Output written to: {initial_output_filename}")
    else:
        print(f"Output potentially split into multiple files starting with '{out_path_base_name}'.")
        print(f"Check files from '{out_path_base_name}{out_ext}' or '{out_path_base_name}_part1{out_ext}' up to '_part{file_part_counter[0]}{out_ext}'.")


# === Main Script ===
def main():
    mode = input("1 = New Report, 2 = Use Existing Report ID: ").strip()
    if mode == "1":
        try:
            report_id, report_title = launch_report()
        except Exception as e:
            print(f"❌ Error launching report: {e}")
            return
    elif mode == "2":
        report_id = input("Enter existing Report ID: ").strip()
        report_title = f"Qualys_Report_{report_id}" 
    else:
        print("Invalid mode selected. Exiting.")
        return

    print(f"📋 Using Report ID: {report_id}, Title: {report_title}")

    while True:
        try:
            status = check_status(report_id)
            print(f"🔄 Report status for ID {report_id}: {status}")
            if status.lower() == "finished":
                file_path = download_report(report_id, report_title)
                break
            elif status.lower() == "error":
                print(f"❌ Report ID {report_id} is in ERROR state. Cannot proceed.")
                return
            else: 
                wait_duration = 600  
                wait_duration_int = int(wait_duration) 
                print(f"⏱ Report not finished. Will retry in {wait_duration_int // 60} minutes.")
                for _ in tqdm(range(wait_duration_int), desc="Waiting for Qualys report", unit="s", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}{postfix}]"):
                    time.sleep(1)
        except requests.exceptions.RequestException as e:
            print(f"Network or API error checking status: {e}. Retrying after a short delay...")
            time.sleep(60) 
        except Exception as e:
            print(f"An unexpected error occurred: {e}. Exiting.")
            return

    match_findings(nessus_file, nessus_sheet, file_path)

if __name__ == "__main__":
    main()
