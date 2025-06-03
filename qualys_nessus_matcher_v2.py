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
import gc # Import garbage collector

# Initialize tqdm for pandas
tqdm.pandas()

# === Constants ===
QUALYS_BASE_URL = "https://qualysapi.qualys.com"
REPORTS_DIR = "reports"
OUTPUT_FORMAT = "csv" # This is for the API download format
HEADERS = {"X-Requested-With": "Python Script"}
MAX_ROWS_PER_FILE = 1048500 # Max rows per Excel sheet/file (slightly less than actual max for safety)


# === Ensure reports directory exists ===
os.makedirs(REPORTS_DIR, exist_ok=True)

# === Global variables for credentials (will be set in main) ===
qualys_username = None
qualys_password = None


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
    # Access global credentials
    global qualys_username, qualys_password
    if not qualys_username or not qualys_password:
        print("❌ Qualys credentials not set. Cannot launch report via API.")
        # This case should ideally be handled before calling launch_report
        # if API interaction is chosen.
        raise Exception("Qualys credentials required for API interaction.")


    report_title = f"Qualys_Report_{int(time.time())}"
    template_id = input("Enter Qualys Report Template ID: ").strip()
    input_type, input_value = build_host_input()

    data = {
        "action": "launch",
        "report_title": report_title,
        "report_type": "Scan",
        "template_id": template_id,
        "output_format": OUTPUT_FORMAT, # API download format
        input_type: input_value
    }

    print("🚀 Launching Qualys report...")
    response = requests.post(
        f"{QUALYS_BASE_URL}/api/2.0/fo/report/",
        data=data,
        headers=HEADERS,
        auth=HTTPBasicAuth(qualys_username, qualys_password)
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
    global qualys_username, qualys_password
    if not qualys_username or not qualys_password:
        raise Exception("Qualys credentials required for API interaction.")

    response = requests.get(
        f"{QUALYS_BASE_URL}/api/2.0/fo/report/",
        params={"action": "list", "id": report_id},
        headers=HEADERS,
        auth=HTTPBasicAuth(qualys_username, qualys_password)
    )
    response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
    root = ET.fromstring(response.text)
    state = root.find(".//REPORT/STATUS/STATE") # Path to state in report list
    return state.text if state is not None else "Unknown"

# === Download Report ===
def download_report(report_id, report_title):
    global qualys_username, qualys_password
    if not qualys_username or not qualys_password:
        raise Exception("Qualys credentials required for API interaction.")

    print(f"⬇️ Attempting to download report ID: {report_id}")
    response = requests.get(
        f"{QUALYS_BASE_URL}/api/2.0/fo/report/",
        params={"action": "fetch", "id": report_id},
        headers=HEADERS,
        auth=HTTPBasicAuth(qualys_username, qualys_password)
    )
    response.raise_for_status() # Ensure download was successful
    
    # The API downloads in the format specified during launch (OUTPUT_FORMAT, which is 'csv')
    filepath = os.path.join(REPORTS_DIR, f"{report_title}.{OUTPUT_FORMAT.lower()}")
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
def match_findings(nessus_file, nessus_sheet, qualys_csv_filepath): # Renamed qualys_file to qualys_csv_filepath for clarity
    try:
        print("🔄 Reading Nessus Excel file...")
        nessus_orig = pd.read_excel(nessus_file, sheet_name=nessus_sheet)
        print(f"🔄 Reading Qualys CSV file from: {qualys_csv_filepath}")
        try:
            # Qualys CSV from API download usually has 6 header rows before data, but original script used 4.
            # Sticking to original skiprows=4. User might need to adjust if format changes.
            qualys_orig = pd.read_csv(qualys_csv_filepath, skiprows=4, low_memory=False) 
        except pd.errors.EmptyDataError:
            print(f"⚠️ Qualys file '{qualys_csv_filepath}' is empty or unreadable after skipping rows. Cannot proceed with matching.")
            return
        except FileNotFoundError:
            print(f"⚠️ Qualys file '{qualys_csv_filepath}' not found. Cannot proceed with matching.")
            return
        except Exception as e:
            print(f"⚠️ Error reading Qualys file '{qualys_csv_filepath}': {e}. Cannot proceed with matching.")
            return

        # Make copies for processing to keep originals if needed (though not strictly used later)
        nessus = nessus_orig.copy()
        del nessus_orig # Free memory of original
        gc.collect()
        qualys = qualys_orig.copy()
        del qualys_orig # Free memory of original
        gc.collect()


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
        gc.collect() # Collect garbage after potentially large explode
        print("   Exploding Qualys CVEs...")
        qualys = qualys.explode("CVEs")
        gc.collect() # Collect garbage

        nessus["CVEs"] = nessus["CVEs"].str.strip()
        qualys["CVEs"] = qualys["CVEs"].str.strip()

        print("🔄 Creating merge keys...")
        nessus["key"] = nessus["IP"].astype(str) + ":" + nessus["Port"].astype(str) + ":" + nessus["CVEs"].astype(str)
        qualys["key"] = qualys["IP"].astype(str) + ":" + qualys["Port"].astype(str) + ":" + qualys["CVEs"].astype(str)

        qualys_keys = set(qualys["key"])
        
        print("🔄 Applying match logic to Nessus data...")
        nessus["Match"] = nessus["key"].progress_apply(lambda k: "Match" if k in qualys_keys else "No Match")
        
        del qualys_keys # Free memory from the set of keys
        gc.collect()

        print("🔄 Generating match summary...")
        # The merge operation itself can be memory intensive
        merged_for_summary = nessus.merge(qualys[["key", "QID", "Vuln Status"]], on="key", how="left")
        gc.collect()

        match_summary = (
            merged_for_summary.groupby(["UniqueID", "IP", "Port", "Reported Finding", "CVEs", "QID", "Vuln Status"], dropna=False) 
            .progress_apply(lambda x: pd.Series({"Match": "Match" if "Match" in x["Match"].values else "No Match"})) 
            .reset_index()
        )
        del merged_for_summary # Free memory from intermediate merge
        gc.collect()
        
    except MemoryError:
        print("❌ Out of Memory Error occurred during data processing (explode, merge, or groupby).")
        print("   Consider processing smaller files or increasing system memory.")
        print("   If the error occurred during 'explode', the input files might have records with an extremely large number of CVEs.")
        return # Exit function on MemoryError
    except KeyError as e:
        print(f"❌ KeyError during data processing: {e}. This often means an expected column name was not found.")
        print(f"   Please check your input file column names and the script's renaming logic.")
        return
    except Exception as e: # Catch any other unexpected error during processing
        print(f"❌ An unexpected error occurred during data processing: {e}")
        return


    # --- Excel Writing with Splitting (Sequential) ---
    out_path_base_name = "nessus_vs_qualys_results"
    out_path_base_dir = os.path.join(REPORTS_DIR, out_path_base_name)
    out_ext = ".xlsx"

    file_part_counter = [0]  
    main_excel_writer = None
    main_writer_status = {'closed': True, 'path': None} 
    
    # Determine initial filename based on the first sheet to be written (match_summary)
    initial_output_filename = f"{out_path_base_dir}{out_ext}"
    if not match_summary.empty and len(match_summary) > MAX_ROWS_PER_FILE:
        file_part_counter[0] = 1 # Start part numbering if first sheet is large
        initial_output_filename = f"{out_path_base_dir}_part{file_part_counter[0]}{out_ext}"
        tqdm.write(f"First sheet ('Match Summary') is large. Initial output file will be: {initial_output_filename}")

    try:
        tqdm.write(f"Creating initial Excel file: {initial_output_filename}")
        main_excel_writer = pd.ExcelWriter(initial_output_filename, engine="openpyxl")
        main_writer_status['closed'] = False 
        main_writer_status['path'] = initial_output_filename
    except Exception as e:
        tqdm.write(f"Error creating initial Excel writer for {initial_output_filename}: {e}")
        print(f"📊 Match results could not be saved due to Excel writer error.")
        return 

    # Write Match Summary
    tqdm.write("Writing 'Match Summary' to Excel...")
    write_dataframe_to_excel_chunks(
        main_excel_writer, match_summary, "Match Summary",
        main_writer_status, file_part_counter, out_path_base_dir, out_ext
    )
    del match_summary # Free memory
    gc.collect()

    # Write Nessus Expanded
    tqdm.write("Writing 'Nessus Expanded' to Excel...")
    current_writer_for_nessus = main_excel_writer if not main_writer_status['closed'] else None
    write_dataframe_to_excel_chunks(
        current_writer_for_nessus, nessus, "Nessus Expanded",
        main_writer_status, file_part_counter, out_path_base_dir, out_ext
    )
    del nessus # Free memory
    gc.collect()

    # Write Qualys Expanded
    tqdm.write("Writing 'Qualys Expanded' to Excel...")
    current_writer_for_qualys = main_excel_writer if not main_writer_status['closed'] else None
    write_dataframe_to_excel_chunks(
        current_writer_for_qualys, qualys, "Qualys Expanded",
        main_writer_status, file_part_counter, out_path_base_dir, out_ext
    )
    del qualys # Free memory
    gc.collect()

    # Final close of the main writer if our status says it's still open
    if main_excel_writer and not main_writer_status['closed']:
        tqdm.write(f"Closing the initial Excel file: {main_writer_status['path']}")
        try:
            main_excel_writer.close()
            main_writer_status['closed'] = True 
        except Exception as e:
            tqdm.write(f"Error during final close of main Excel writer {main_writer_status['path']}: {e}")
    elif main_excel_writer and main_writer_status['closed']: 
        tqdm.write(f"Initial Excel writer ({main_writer_status.get('path', 'N/A')}) was already considered closed or handled by chunking.")

    print(f"📊 Match results processing complete.")
    if file_part_counter[0] == 0: 
        print(f"Output written to: {initial_output_filename}") 
    elif file_part_counter[0] == 1 and initial_output_filename.endswith(f"_part1{out_ext}"):
        print(f"Output written to: {initial_output_filename}")
    else:
        print(f"Output potentially split into multiple files starting with '{out_path_base_name}'.")
        print(f"Check files from '{out_path_base_dir}{out_ext}' (if first sheet was small) or '{out_path_base_dir}_part1{out_ext}' up to '_part{file_part_counter[0]}{out_ext}'.")


# === Main Script ===
def main():
    # Access global credentials to set them
    global qualys_username, qualys_password

    qualys_report_filepath = None # Will store the path to the Qualys CSV report

    # === Get Nessus file info first (as it's always needed) ===
    # Moved Nessus input here as it's independent of Qualys source
    nessus_file_path_input = input("Enter Nessus Excel filename: ").strip()
    nessus_sheet_name_input = input("Enter Nessus sheet name: ").strip()


    # === New prompt for Qualys report source ===
    has_downloaded_qualys = input("Have you already downloaded the Qualys report as a CSV? (yes/no): ").strip().lower()

    if has_downloaded_qualys == 'yes':
        qualys_report_filepath = input("Enter the full path to your downloaded Qualys CSV report: ").strip()
        if not os.path.exists(qualys_report_filepath):
            print(f"❌ Error: Provided Qualys report file '{qualys_report_filepath}' not found. Exiting.")
            return
        print(f"👍 Using existing Qualys report: {qualys_report_filepath}")
    else:
        print("ℹ️ Will proceed to fetch Qualys report via API.")
        # Get Qualys credentials only if using API
        qualys_username = input("Qualys Username: ")
        qualys_password = getpass("Qualys Password: ")

        mode = input("1 = Launch New Qualys Report via API, 2 = Use Existing Report ID via API: ").strip()
        if mode == "1":
            try:
                report_id, report_title = launch_report()
            except Exception as e:
                print(f"❌ Error launching report: {e}")
                return
        elif mode == "2":
            report_id = input("Enter existing Qualys Report ID: ").strip()
            report_title = f"Qualys_Report_{report_id}" 
        else:
            print("Invalid mode selected for API interaction. Exiting.")
            return

        print(f"📋 Using Qualys Report ID: {report_id}, Title: {report_title} (via API)")

        while True:
            try:
                status = check_status(report_id)
                print(f"🔄 Report status for ID {report_id}: {status}")
                if status.lower() == "finished":
                    qualys_report_filepath = download_report(report_id, report_title)
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
                print(f"An unexpected error occurred during API report fetching: {e}. Exiting.")
                return
    
    if not qualys_report_filepath:
        print("❌ No Qualys report file available (either not provided or API fetch failed). Exiting.")
        return

    # Call match_findings with the determined Qualys report path and Nessus inputs
    match_findings(nessus_file_path_input, nessus_sheet_name_input, qualys_report_filepath)

if __name__ == "__main__":
    main()
