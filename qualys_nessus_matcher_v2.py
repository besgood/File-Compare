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
# MAX_ROWS_PER_FILE = 500000 # Example: Lowered to 500,000 rows if memory/Excel opening is an issue


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
    response.raise_for_status() 
    root = ET.fromstring(response.text)
    state = root.find(".//REPORT/STATUS/STATE") 
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
    response.raise_for_status() 
    
    filepath = os.path.join(REPORTS_DIR, f"{report_title}.{OUTPUT_FORMAT.lower()}")
    with open(filepath, "wb") as f:
        f.write(response.content)
    print(f"✅ Report downloaded to: {filepath}")
    return filepath

# === Helper function to write DataFrames to Excel in chunks ===
def write_dataframe_to_excel_chunks(writer, df, sheet_name, main_writer_status, current_file_index_ref, base_output_filename_no_ext, ext):
    num_rows = len(df)
    if num_rows == 0:
        tqdm.write(f"Sheet '{sheet_name}' has no data. Attempting to write an empty sheet.")
        if writer and not main_writer_status['closed']: 
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
    if writer and not main_writer_status['closed']:
        try:
            tqdm.write(f"Writing first chunk of '{sheet_name}' ({len(first_chunk_df)} rows) to: {main_writer_status['path']}")
            first_chunk_df.to_excel(writer, sheet_name=sheet_name, index=False)
            wrote_first_chunk_to_initial_writer = True
        except Exception as e:
            tqdm.write(f"Error writing first chunk of '{sheet_name}' to {main_writer_status['path']}: {e}. Will attempt new file.")
            main_writer_status['closed'] = True 

    if not wrote_first_chunk_to_initial_writer:
        current_file_index_ref[0] += 1
        output_filename_part = f"{base_output_filename_no_ext}_part{current_file_index_ref[0]}{ext}"
        tqdm.write(f"Writing first chunk of '{sheet_name}' ({len(first_chunk_df)} rows) to new file: {output_filename_part}")
        with pd.ExcelWriter(output_filename_part, engine='openpyxl') as chunk_writer:
            first_chunk_df.to_excel(chunk_writer, sheet_name=sheet_name, index=False)
        
        if writer and not main_writer_status['closed']:
            tqdm.write(f"Closing initial writer {main_writer_status['path']} as '{sheet_name}' (or its first chunk) is moved to new files.")
            try:
                writer.close()
            except Exception as e: 
                tqdm.write(f"Note: Error closing initial writer (it might have been closed due to prior error): {e}")
            main_writer_status['closed'] = True

    num_total_chunks = (num_rows + MAX_ROWS_PER_FILE - 1) // MAX_ROWS_PER_FILE
    for i in range(1, num_total_chunks): 
        start_row = i * MAX_ROWS_PER_FILE
        end_row = min((i + 1) * MAX_ROWS_PER_FILE, num_rows)
        chunk_df = df.iloc[start_row:end_row]

        if chunk_df.empty:
            continue

        if writer and not main_writer_status['closed'] and wrote_first_chunk_to_initial_writer:
            tqdm.write(f"Closing initial writer {main_writer_status['path']} before creating new file for chunk {i+1} of '{sheet_name}'.")
            try:
                writer.close()
            except Exception as e:
                tqdm.write(f"Note: Error closing initial writer (it might have been closed due to prior error): {e}")
            main_writer_status['closed'] = True 

        current_file_index_ref[0] += 1
        output_filename_part = f"{base_output_filename_no_ext}_part{current_file_index_ref[0]}{ext}"
        tqdm.write(f"Writing chunk {i+1} of '{sheet_name}' ({len(chunk_df)} rows) to new file: {output_filename_part}")
        with pd.ExcelWriter(output_filename_part, engine='openpyxl') as chunk_writer:
            chunk_df.to_excel(chunk_writer, sheet_name=sheet_name, index=False)


# === Match Nessus and Qualys Data ===
def match_findings(nessus_file, nessus_sheet, qualys_csv_filepath): 
    try:
        print("🔄 Reading Nessus Excel file...")
        nessus_orig = pd.read_excel(nessus_file, sheet_name=nessus_sheet)
        print(f"🔄 Reading Qualys CSV file from: {qualys_csv_filepath}")
        try:
            qualys_orig = pd.read_csv(qualys_csv_filepath, skiprows=6, low_memory=False) 
        except pd.errors.EmptyDataError:
            print(f"⚠️ Qualys file '{qualys_csv_filepath}' is empty or unreadable after skipping rows. Cannot proceed with matching.")
            return
        except FileNotFoundError:
            print(f"⚠️ Qualys file '{qualys_csv_filepath}' not found. Cannot proceed with matching.")
            return
        except Exception as e:
            print(f"⚠️ Error reading Qualys file '{qualys_csv_filepath}': {e}. Cannot proceed with matching.")
            return

        nessus = nessus_orig.copy()
        del nessus_orig 
        gc.collect()
        qualys = qualys_orig.copy()
        del qualys_orig 
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
                original_name_map = {"IP": "IP Address", "CVEs": "CVE", "UniqueID": "Unique ID"}
                expected_orig = original_name_map.get(col, "an expected original column")
                raise KeyError(f"Nessus DataFrame missing required column '{col}' (expected from '{expected_orig}') after rename. Available: {list(nessus.columns)}")
        for col in required_qualys_cols:
            if col not in qualys.columns:
                original_name_map = {"CVEs": "CVE ID", "Vuln Status": "Vulnerability State"}
                expected_orig = original_name_map.get(col, "an expected original column")
                raise KeyError(f"Qualys DataFrame missing required column '{col}' (expected from '{expected_orig}') after rename. Available: {list(qualys.columns)}. Check 'skiprows' value for Qualys CSV.")

        print("🔄 Normalizing data types and stripping whitespace for key components...")
        for df_name, df_obj in [("Nessus", nessus), ("Qualys", qualys)]:
            for col in ["IP", "Port", "CVEs"]:
                if col in df_obj.columns:
                    df_obj[col] = df_obj[col].fillna('').astype(str).str.strip() 
                else:
                    print(f"⚠️ Warning: Column '{col}' not found in {df_name} DataFrame during normalization.")
        
        print("🔄 Processing CVEs (splitting and exploding)...")
        nessus["CVEs"] = nessus["CVEs"].str.split(",")
        qualys["CVEs"] = qualys["CVEs"].str.split(",")

        print("   Exploding Nessus CVEs...")
        nessus = nessus.explode("CVEs")
        gc.collect() 
        print("   Exploding Qualys CVEs...")
        qualys = qualys.explode("CVEs")
        gc.collect() 

        nessus["CVEs"] = nessus["CVEs"].str.strip()
        qualys["CVEs"] = qualys["CVEs"].str.strip()
        
        print("🔄 Creating merge keys...")
        nessus["key"] = nessus["IP"] + ":" + nessus["Port"] + ":" + nessus["CVEs"]
        qualys["key"] = qualys["IP"] + ":" + qualys["Port"] + ":" + qualys["CVEs"]

        qualys_keys = set(qualys["key"])
        
        print("🔄 Applying match logic to Nessus data...")
        nessus["Match"] = nessus["key"].progress_apply(lambda k: "Match" if k in qualys_keys else "No Match")
        
        match_counts_after_apply = nessus["Match"].value_counts()
        print("\n--- Match Counts in Nessus Data (after .progress_apply): ---")
        print(match_counts_after_apply)
        if "Match" not in match_counts_after_apply or match_counts_after_apply.get("Match", 0) == 0: # Use .get for safety
            print("⚠️ WARNING: Zero matches found after applying logic. Please check diagnostic prints if uncommented, and verify data consistency (IPs, Ports, CVEs) between Nessus and Qualys sources.")
        print("-" * 50)

        del qualys_keys 
        gc.collect()

        print("🔄 Generating match summary...")
        # Preserve the 'key' from nessus through the merge for inclusion in the summary
        nessus_for_merge = nessus[["key", "UniqueID", "IP", "Port", "Reported Finding", "CVEs", "Match"]].copy()
        qualys_for_merge = qualys[["key", "QID", "Vuln Status"]].drop_duplicates(subset=['key']).copy() # Avoid duplicate keys from Qualys if any

        merged_for_summary = nessus_for_merge.merge(qualys_for_merge, on="key", how="left")
        del nessus_for_merge, qualys_for_merge # Free memory
        gc.collect()

        # Group by fields, including the 'key' now.
        # The lambda function for 'Match' status in groupby might be redundant if 'Match' column from nessus is already correct.
        # Let's simplify the groupby and ensure 'key' is part of it or added back.
        
        # The 'Match' column is already determined in the 'nessus' DataFrame.
        # We need to ensure the groupby operation correctly aggregates while keeping the 'key'.
        # Since 'key' is unique for each IP:Port:CVE combination in the exploded Nessus data,
        # and we are grouping by IP, Port, CVEs (components of the key), plus other fields,
        # the 'key' will be consistent within each group. We can select it via .first() or just include it.

        group_by_cols = ["UniqueID", "IP", "Port", "Reported Finding", "CVEs", "key", "QID", "Vuln Status"] # Added "key"
        
        # If 'Match' is already correctly determined per row in 'merged_for_summary' (from 'nessus'),
        # the groupby is mainly for structuring and potentially handling cases where a Nessus finding
        # might map to multiple Qualys QIDs if CVEs are not perfectly one-to-one (though less likely with current key).
        # The original groupby's apply was to ensure 'Match' status if any part of a group matched.
        # Given 'key' is now very specific, this might simplify.

        # Let's keep the original groupby logic for 'Match' but ensure 'key' is a grouping column.
        # The `progress_apply` for Match status should still work.
        # The `key` is now part of the `groupby` columns.
        
        match_summary_grouped = merged_for_summary.groupby(
            group_by_cols, # 'key' is now a grouping column
            dropna=False
        )
        
        # Apply the function to determine overall match status for the group
        # This lambda was: lambda x: pd.Series({"Match": "Match" if "Match" in x["Match"].values else "No Match"})
        # Since 'Match' is already in merged_for_summary, we can just take its first value for the group,
        # as it should be consistent within the group defined by the unique key.
        # Or, if there's a scenario where multiple rows from `merged_for_summary` form one group in `match_summary`
        # (e.g., if UniqueID, ReportedFinding are less granular than IP:Port:CVE), then the original logic is safer.
        # Given the group_by_cols, each group should have a consistent 'Match' status from the nessus part.
        # So, we can just select the columns we need.
        
        # Simpler approach: select columns and drop duplicates if groupby isn't strictly for aggregation here.
        # However, the original groupby was:
        # .groupby(["UniqueID", "IP", "Port", "Reported Finding", "CVEs", "QID", "Vuln Status"], dropna=False)
        # .progress_apply(lambda x: pd.Series({"Match": "Match" if "Match" in x["Match"].values else "No Match"}))
        # Let's try to preserve this intent but include 'key'.
        # The 'key' is made of IP, Port, CVEs. If these are in groupby, 'key' is implicitly handled.
        # We just need to add 'key' to the output.
        
        # Reconstruct key in the summary if it's dropped by groupby
        # Or, ensure 'key' is part of the group by and thus in the reset_index()
        
        # The 'key' column was in `nessus` and thus in `merged_for_summary`.
        # If we group by its components (IP, Port, CVEs), the key is implicitly defined for each group.
        # We want the key in the final output.
        
        # Let's adjust the groupby slightly to ensure 'key' is preserved or easily added.
        # The original groupby was on UniqueID, IP, Port, Reported Finding, CVEs, QID, Vuln Status.
        # The 'key' is IP:Port:CVEs. These are already grouping columns.
        
        # We'll add 'key' to the `merged_for_summary` columns that are carried to `match_summary`
        
        match_summary = (
            merged_for_summary.groupby(
                ["UniqueID", "IP", "Port", "Reported Finding", "CVEs", "QID", "Vuln Status"], # Original groupby cols
                dropna=False
            )
            .agg(
                Match_Status=('Match', 'first'), # Get the match status (should be consistent per group)
                Match_Key=('key', 'first')      # Get the key for this group
            )
            .reset_index()
        )
        # Rename Match_Status back to Match for consistency with original output
        match_summary.rename(columns={'Match_Status': 'Match', 'Match_Key': 'Key Used for Match'}, inplace=True)


        del merged_for_summary 
        gc.collect()
        
    except MemoryError:
        print("❌ Out of Memory Error occurred during data processing (explode, merge, or groupby).")
        print("   Consider processing smaller files or increasing system memory.")
        print("   If the error occurred during 'explode', the input files might have records with an extremely large number of CVEs.")
        return 
    except KeyError as e:
        print(f"❌ KeyError during data processing: {e}. This often means an expected column name was not found.")
        print(f"   Please check your input file column names and the script's renaming logic.")
        return
    except Exception as e: 
        print(f"❌ An unexpected error occurred during data processing: {e}")
        return


    # --- Excel Writing with Splitting (Sequential) ---
    out_path_base_name = "nessus_vs_qualys_results"
    out_path_base_dir = os.path.join(REPORTS_DIR, out_path_base_name)
    out_ext = ".xlsx"

    file_part_counter = [0]  
    main_excel_writer = None
    main_writer_status = {'closed': True, 'path': None} 
    
    initial_output_filename = f"{out_path_base_dir}{out_ext}"
    if not match_summary.empty and len(match_summary) > MAX_ROWS_PER_FILE:
        file_part_counter[0] = 1 
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

    # Only write Match Summary now
    tqdm.write("Writing 'Match Summary' to Excel...")
    write_dataframe_to_excel_chunks(
        main_excel_writer, match_summary, "Match Summary",
        main_writer_status, file_part_counter, out_path_base_dir, out_ext
    )
    del match_summary 
    gc.collect()

    # --- Removed writing of Nessus Expanded and Qualys Expanded ---
    # tqdm.write("Writing 'Nessus Expanded' to Excel...")
    # current_writer_for_nessus = main_excel_writer if not main_writer_status['closed'] else None
    # write_dataframe_to_excel_chunks(
    #     current_writer_for_nessus, nessus, "Nessus Expanded",
    #     main_writer_status, file_part_counter, out_path_base_dir, out_ext
    # )
    # del nessus 
    # gc.collect()

    # tqdm.write("Writing 'Qualys Expanded' to Excel...")
    # current_writer_for_qualys = main_excel_writer if not main_writer_status['closed'] else None
    # write_dataframe_to_excel_chunks(
    #     current_writer_for_qualys, qualys, "Qualys Expanded",
    #     main_writer_status, file_part_counter, out_path_base_dir, out_ext
    # )
    # del qualys 
    # gc.collect()

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
    global qualys_username, qualys_password

    qualys_report_filepath = None 

    nessus_file_path_input = input("Enter Nessus Excel filename: ").strip()
    nessus_sheet_name_input = input("Enter Nessus sheet name: ").strip()

    has_downloaded_qualys = input("Have you already downloaded the Qualys report as a CSV? (yes/no): ").strip().lower()

    if has_downloaded_qualys == 'yes':
        qualys_report_filepath = input("Enter the full path to your downloaded Qualys CSV report: ").strip()
        if not os.path.exists(qualys_report_filepath):
            print(f"❌ Error: Provided Qualys report file '{qualys_report_filepath}' not found. Exiting.")
            return
        print(f"👍 Using existing Qualys report: {qualys_report_filepath}")
    else:
        print("ℹ️ Will proceed to fetch Qualys report via API.")
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

    match_findings(nessus_file_path_input, nessus_sheet_name_input, qualys_report_filepath)

if __name__ == "__main__":
    main()
