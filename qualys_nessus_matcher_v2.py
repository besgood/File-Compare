import pandas as pd
import numpy as np
import ipaddress
import re
from tqdm.auto import tqdm # For progress bars
import os # For path manipulation
import requests # For Qualys API calls
from getpass import getpass # For secure password input
import xml.etree.ElementTree as ET # For parsing Qualys API XML response

# Initialize tqdm for pandas
tqdm.pandas()

# --- Configuration (Defaults) ---
DEFAULT_QUALYS_API_URL = 'https://qualysapi.qualys.com' # Example, replace with your Qualys API gateway URL
DEFAULT_NESSUS_CSV = 'nessus_report.csv'
DEFAULT_OUTPUT_EXCEL = 'vulnerability_comparison.xlsx' # Base name for output
DEFAULT_CVSS_SCORE_CUTOFF = 7.0
QUALYS_API_PAGE_SIZE = 1000 # Number of detections to fetch per API call during pagination

MAX_ROWS_PER_FILE = 1048500 # Max rows per Excel sheet/file (slightly less than actual max for safety)

# --- Helper Functions ---
def is_ip_address(string):
    """Checks if a string is a valid IP address."""
    if pd.isna(string):
        return False
    try:
        ipaddress.ip_address(string)
        return True
    except ValueError:
        return False

def clean_qualys_ip_csv(ip_str): # Renamed to specify CSV context if different cleaning is needed
    """Extracts the first valid IP address from a Qualys IP string (primarily for CSV)."""
    if pd.isna(ip_str):
        return None
    match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', str(ip_str))
    return match.group(0) if match else None

def clean_nessus_host(host_str):
    """Cleans the Nessus host string. Returns IP if it's an IP, otherwise the original string."""
    if pd.isna(host_str):
        return None
    host_str_cleaned = str(host_str).strip()
    if is_ip_address(host_str_cleaned):
        return host_str_cleaned
    return host_str_cleaned 

def normalize_plugin_id(plugin_id):
    """Normalizes plugin ID to its integer part as a string. Handles potential hex QIDs from Qualys."""
    if pd.isna(plugin_id):
        return None
    pid_str = str(plugin_id)
    if pid_str.startswith("0x") or pid_str.startswith("0X"): # Check if it's a hex string (case-insensitive)
        try:
            return str(int(pid_str, 16)) # Convert hex to decimal string
        except ValueError:
            # If conversion fails, try to split (e.g., if it's like "0xABC.1")
            return pid_str.split('.')[0] 
    return pid_str.split('.')[0]


def fetch_qualys_detections_to_dataframe(api_url, username, password):
    """
    Fetches host detections from Qualys API and parses them into a Pandas DataFrame.
    Outputs columns with names closer to CSV for easier downstream processing.
    Handles basic pagination.
    """
    print("Attempting to fetch data from Qualys API...")
    print("IMPORTANT: Fetching all detections without specific filters (e.g., IPs, asset_groups, detection_updated_since)")
    print("on a large Qualys subscription can be very time-consuming and resource-intensive.")
    print(f"Using API page size: {QUALYS_API_PAGE_SIZE}")

    detections_list = []
    headers = {
        'X-Requested-With': 'Python Script',
    }
    detection_api_url = f"{api_url.rstrip('/')}/api/2.0/fo/asset/host/vm/detection/"
    
    params = {
        "action": "list",
        "truncation_limit": QUALYS_API_PAGE_SIZE,
        "output_format": "XML", # Explicitly request XML
        # Consider adding: "show_results": "1" if not default, "show_cvss_tags":"1"
    }

    page_count = 0
    while True:
        page_count += 1
        print(f"Fetching Qualys API data - Page {page_count} (Params: {params})...")
        try:
            response = requests.get(
                detection_api_url,
                headers=headers,
                auth=(username, password),
                params=params,
                timeout=300 # Increased timeout for potentially large requests
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error during Qualys API request: {e}")
            if page_count > 1: print("Returning partially fetched data due to API error.")
            break 
        if not response.content:
            print("Empty response from Qualys API. Stopping.")
            break
        try:
            root = ET.fromstring(response.content)
        except ET.ParseError as e:
            print(f"Error parsing Qualys API XML response: {e}")
            print(f"Response content (first 500 chars): {response.text[:500]}")
            if page_count > 1: print("Returning partially fetched data due to XML parsing error.")
            break

        host_list_node = root.find('HOST_LIST')
        if host_list_node is None:
            code_node = root.find('.//CODE') # Check for specific error codes
            message_node = root.find('.//MESSAGE')
            if code_node is not None:
                print(f"Qualys API Info/Error Code: {code_node.text}")
            if message_node is not None:
                print(f"Qualys API Message: {message_node.text}")
            if page_count == 1 : print("No HOST_LIST found in the first API response. This might mean no detections matched or an issue with the query/permissions.")
            else: print("No HOST_LIST found in subsequent API response.")
            break

        current_page_detections = 0
        for host_node in host_list_node.findall('HOST'):
            ip_address = host_node.findtext('IP')
            dns_name = host_node.findtext('DNS')
            netbios_name = host_node.findtext('NETBIOS')
            os_full = host_node.findtext('OPERATING_SYSTEM')
            
            detection_list_node = host_node.find('DETECTION_LIST')
            if detection_list_node is not None:
                for detection_node in detection_list_node.findall('DETECTION'):
                    current_page_detections += 1
                    
                    qid_raw = detection_node.findtext('QID')
                    qid_normalized = normalize_plugin_id(qid_raw) # Normalize QID here

                    # Use QID for Title placeholder if actual title not in this API view
                    title_placeholder = f"QID-{qid_normalized}" 
                    # Some API versions might have <VULN_INFO_LIST><VULN_INFO><TITLE>
                    # For simplicity, we use QID as title if not found.

                    severity_val = detection_node.findtext('SEVERITY')
                    port_val = detection_node.findtext('PORT')
                    protocol_val = detection_node.findtext('PROTOCOL')
                    results_val = detection_node.findtext('RESULTS')
                    ssl_flag = detection_node.findtext('SSL') == '1'
                    type_val = detection_node.findtext('TYPE') # Confirmed, Potential, Info

                    cvss_base_score = None
                    # Prefer CVSS v3
                    cvss_v3_data = detection_node.find('CVSS_V3')
                    if cvss_v3_data is not None and cvss_v3_data.findtext('BASE') is not None:
                        cvss_base_score = cvss_v3_data.findtext('BASE')
                    else: # Fallback to CVSS v2
                        cvss_data = detection_node.find('CVSS')
                        if cvss_data is not None and cvss_data.findtext('BASE') is not None:
                            cvss_base_score = cvss_data.findtext('BASE')
                    
                    detections_list.append({
                        'IP': ip_address,
                        'QID': qid_normalized, # This is the key for merging, already normalized
                        'Title': title_placeholder, 
                        'Severity': severity_val,
                        'CVSS Base': cvss_base_score,
                        'Results': results_val,
                        'DNS Name': dns_name,
                        'NetBIOS Name': netbios_name,
                        'OS': os_full,
                        'Port': port_val, # Keep for Qualys-specific info
                        'Protocol': protocol_val, # Keep for Qualys-specific info
                        'SSL': ssl_flag, # Keep for Qualys-specific info
                        'Detection_Type': type_val # Keep for Qualys-specific info
                    })
        
        print(f"Fetched {current_page_detections} detections on page {page_count}.")
        
        if current_page_detections == 0 and page_count > 1:
            print("Fetched 0 detections on a subsequent page, assuming end of data.")
            break
        if current_page_detections < QUALYS_API_PAGE_SIZE :
            print("Fewer results than page size, assuming end of data for Qualys API.")
            break
            
        # Pagination: Check for 'last_id' in the warning URL or HAS_MORE_RECORDS
        has_more_records_node = root.find('.//RESPONSE/HAS_MORE_RECORDS') # More reliable
        next_page_url_node = root.find('.//RESPONSE/WARNING/URL') # Fallback check

        if has_more_records_node is not None and has_more_records_node.text == '1':
            # Try to extract last_id from the URL if present
            if next_page_url_node is not None and 'last_id=' in next_page_url_node.text:
                try:
                    last_id_val = re.search(r'last_id=(\d+)', next_page_url_node.text).group(1)
                    params["id_min"] = str(int(last_id_val) + 1)
                    print(f"Paginating: Next request will use id_min based on last_id={last_id_val}")
                except (AttributeError, ValueError) as e:
                    print(f"Could not extract last_id for pagination from URL: {e}. Stopping pagination. Data might be incomplete if many results.")
                    break
            else:
                # If HAS_MORE_RECORDS is 1 but no last_id in URL, this pagination method might not be sufficient.
                # The API might require using the last seen QID or internal ID if `id_min` is based on that.
                # This is a complex scenario. For now, we'll warn and break.
                print("API indicates more records, but no 'last_id' found in the next page URL for simple pagination.")
                print("This script's pagination might be incomplete for very large datasets without more specific filters.")
                print("Consider adding filters like 'detection_updated_since' or 'ips' to your API call.")
                break
        else: # No HAS_MORE_RECORDS tag or it's not '1'
            print("No more results indicated by Qualys API or pagination unclear.")
            break

    if not detections_list:
        print("No detections fetched from Qualys API.")
        return pd.DataFrame() # Ensure empty DataFrame is returned
        
    df = pd.DataFrame(detections_list)
    print(f"Successfully fetched and parsed {len(df)} total detections from Qualys API.")
    return df


def write_dataframe_to_excel_chunks(writer, df, sheet_name, main_writer_status, current_file_index_ref, base_output_filename):
    """
    Writes a large DataFrame to one or more Excel files, chunked by MAX_ROWS_PER_FILE.
    """
    num_rows = len(df)
    if num_rows == 0:
        print(f"Sheet '{sheet_name}' has no data. Attempting to write an empty sheet.")
        if writer and not writer.closed and not main_writer_status['closed']:
            try:
                pd.DataFrame().to_excel(writer, sheet_name=sheet_name, index=False)
                print(f"Empty sheet '{sheet_name}' written to: {main_writer_status['path']}")
            except Exception as e:
                print(f"Error writing empty sheet '{sheet_name}' to {main_writer_status['path']}: {e}")
        else:
            print(f"Main writer for '{sheet_name}' is not available or closed, and sheet is empty. Skipping file creation for empty sheet.")
        return

    first_chunk_df = df.iloc[:MAX_ROWS_PER_FILE]
    
    wrote_first_chunk_to_initial_writer = False
    if writer and not writer.closed and not main_writer_status['closed']:
        try:
            print(f"Writing first chunk of '{sheet_name}' ({len(first_chunk_df)} rows) to: {main_writer_status['path']}")
            first_chunk_df.to_excel(writer, sheet_name=sheet_name, index=False)
            wrote_first_chunk_to_initial_writer = True
        except Exception as e:
            print(f"Error writing first chunk of '{sheet_name}' to {main_writer_status['path']}: {e}. Will attempt new file.")
            main_writer_status['closed'] = True 

    if not wrote_first_chunk_to_initial_writer:
        current_file_index_ref[0] += 1
        output_filename_part = f"{os.path.splitext(base_output_filename)[0]}_part{current_file_index_ref[0]}{os.path.splitext(base_output_filename)[1]}"
        print(f"Writing first chunk of '{sheet_name}' ({len(first_chunk_df)} rows) to new file: {output_filename_part}")
        with pd.ExcelWriter(output_filename_part, engine='xlsxwriter') as chunk_writer:
            first_chunk_df.to_excel(chunk_writer, sheet_name=sheet_name, index=False)
        if writer and not writer.closed and not main_writer_status['closed']: # If initial writer existed but wasn't used for 1st chunk
            print(f"Closing initial writer {main_writer_status['path']} as '{sheet_name}' (or its first chunk) is moved to new files.")
            writer.close()
            main_writer_status['closed'] = True

    num_total_chunks = (num_rows + MAX_ROWS_PER_FILE - 1) // MAX_ROWS_PER_FILE
    for i in range(1, num_total_chunks): 
        start_row = i * MAX_ROWS_PER_FILE
        end_row = min((i + 1) * MAX_ROWS_PER_FILE, num_rows)
        chunk_df = df.iloc[start_row:end_row]

        if chunk_df.empty:
            continue

        # This check ensures the initial writer (if it was used for the first chunk) is closed before new files are made
        if writer and not writer.closed and not main_writer_status['closed'] and wrote_first_chunk_to_initial_writer:
            print(f"Closing initial writer {main_writer_status['path']} before creating new file for chunk {i+1} of '{sheet_name}'.")
            writer.close()
            main_writer_status['closed'] = True 

        current_file_index_ref[0] += 1
        output_filename_part = f"{os.path.splitext(base_output_filename)[0]}_part{current_file_index_ref[0]}{os.path.splitext(base_output_filename)[1]}"
        print(f"Writing chunk {i+1} of '{sheet_name}' ({len(chunk_df)} rows) to new file: {output_filename_part}")
        with pd.ExcelWriter(output_filename_part, engine='xlsxwriter') as chunk_writer:
            chunk_df.to_excel(chunk_writer, sheet_name=sheet_name, index=False)


# --- Main Script ---
def main():
    print("Starting vulnerability comparison script...")

    # --- Get User Inputs ---
    use_qualys_api = input("Use Qualys API to fetch data? (yes/no, default: yes): ").strip().lower()
    if use_qualys_api == "": use_qualys_api = "yes"

    qualys_df_full = pd.DataFrame() # Initialize empty DataFrame

    if use_qualys_api == 'yes':
        qualys_api_url = input(f"Enter Qualys API Gateway URL (default: {DEFAULT_QUALYS_API_URL}): ") or DEFAULT_QUALYS_API_URL
        qualys_username = input("Enter Qualys API Username: ")
        qualys_password = getpass("Enter Qualys API Password: ")
        if not (qualys_api_url and qualys_username and qualys_password):
            print("Qualys API URL, Username, or Password not provided. Will attempt CSV fallback.")
            use_qualys_api = 'no' 
        else:
            qualys_df_full = fetch_qualys_detections_to_dataframe(qualys_api_url, qualys_username, qualys_password)
            if qualys_df_full.empty:
                print("Failed to fetch data from Qualys API or no data returned. Will attempt CSV fallback if path provided.")
                # Do not exit yet, allow CSV fallback
    
    if use_qualys_api != 'yes' or qualys_df_full.empty: 
        qualys_csv_path_default = 'qualys_report.csv' 
        qualys_csv_path = input(f"Enter path to Qualys CSV report (default: {qualys_csv_path_default}): ") or qualys_csv_path_default
        if os.path.exists(qualys_csv_path):
            print(f"Loading Qualys report from CSV: {qualys_csv_path}")
            try:
                qualys_df_from_csv = pd.read_csv(qualys_csv_path, low_memory=False)
                print(f"Qualys CSV report loaded: {qualys_df_from_csv.shape[0]} rows, {qualys_df_from_csv.shape[1]} columns.")
                if qualys_df_full.empty: # If API failed or was skipped, use CSV
                    qualys_df_full = qualys_df_from_csv
                # If API succeeded, qualys_df_full already has data. We prioritize API if both somehow exist.
            except FileNotFoundError: # Should be caught by os.path.exists, but good to have
                print(f"Error: Qualys report file '{qualys_csv_path}' not found.")
                if qualys_df_full.empty: # If API also failed/skipped and CSV not found
                     print("No Qualys data source available (API failed/skipped and CSV not found). Exiting.")
                     return
            except Exception as e:
                print(f"Error loading Qualys CSV report: {e}")
                if qualys_df_full.empty:
                     print("No Qualys data source available. Exiting.")
                     return
        elif qualys_df_full.empty: # CSV path doesn't exist AND API data is also empty
            print(f"Qualys CSV file '{qualys_csv_path}' not found, and API data was not fetched/empty. Exiting.")
            return

    if qualys_df_full.empty:
        print("No Qualys data could be loaded. Exiting.")
        return

    nessus_csv_path = input(f"Enter path to Nessus CSV report (default: {DEFAULT_NESSUS_CSV}): ") or DEFAULT_NESSUS_CSV
    output_excel_path = input(f"Enter desired output Excel filename (default: {DEFAULT_OUTPUT_EXCEL}): ") or DEFAULT_OUTPUT_EXCEL
    
    cvss_cutoff_str = input(f"Enter CVSS score cutoff (e.g., 7.0, default: {DEFAULT_CVSS_SCORE_CUTOFF}): ") or str(DEFAULT_CVSS_SCORE_CUTOFF)
    try:
        cvss_score_cutoff = float(cvss_cutoff_str)
    except ValueError:
        print(f"Invalid CVSS score '{cvss_cutoff_str}'. Using default: {DEFAULT_CVSS_SCORE_CUTOFF}")
        cvss_score_cutoff = DEFAULT_CVSS_SCORE_CUTOFF

    # --- 1. Load Nessus Data (Qualys data already in qualys_df_full) ---
    print(f"Loading Nessus report from: {nessus_csv_path}")
    try:
        nessus_df_full = pd.read_csv(nessus_csv_path, low_memory=False)
        print(f"Nessus report loaded: {nessus_df_full.shape[0]} rows, {nessus_df_full.shape[1]} columns.")
    except FileNotFoundError:
        print(f"Error: Nessus report file '{nessus_csv_path}' not found. Please check the path and filename.")
        return
    except Exception as e:
        print(f"Error loading Nessus report: {e}")
        return

    # --- 2. Preprocessing and Cleaning ---
    print("Preprocessing and cleaning data...")

    # Qualys Preprocessing
    # Check if columns suggest it's from API (e.g., 'Detection_Type' exists, or 'IP', 'QID' are direct from API)
    # or from CSV (needs more mapping).
    # The fetch_qualys_detections_to_dataframe now outputs columns like 'IP', 'QID', 'Title', 'Severity', 'CVSS Base'
    is_qualys_api_data = 'Detection_Type' in qualys_df_full.columns or \
                         ('IP' in qualys_df_full.columns and 'QID' in qualys_df_full.columns and \
                          'Title' in qualys_df_full.columns and 'Severity' in qualys_df_full.columns and \
                          'CVSS Base' in qualys_df_full.columns and 'Results' in qualys_df_full.columns)


    if is_qualys_api_data and use_qualys_api == 'yes': # Prioritize if API was intended and structure matches
        print("Processing Qualys data (source: API)...")
        qualys_df_cleaned = qualys_df_full.copy()
        # API data's 'IP' is generally clean. 'QID' from API is already normalized by fetch_qualys_detections_to_dataframe.
        qualys_df_cleaned.loc[:, 'Clean_IP'] = qualys_df_cleaned['IP'] 
        qualys_df_cleaned.loc[:, 'Plugin_ID_Normalized'] = qualys_df_cleaned['QID'] # QID from API is already normalized string
        
        # Rename to standard internal names for merging consistency
        qualys_df_cleaned.rename(columns={
            'Title': 'Qualys_Title',
            'Severity': 'Qualys_Severity',
            'CVSS Base': 'Qualys_CVSS',
            'Results': 'Qualys_Results'
            # 'DNS Name', 'NetBIOS Name', 'OS' are already named as expected by fetch function
        }, inplace=True)
        # Ensure original 'QID' (which is Plugin_ID_Normalized from API) is present if needed for reports
        if 'QID' not in qualys_df_cleaned.columns and 'Plugin_ID_Normalized' in qualys_df_cleaned.columns:
             qualys_df_cleaned['QID'] = qualys_df_cleaned['Plugin_ID_Normalized']


    else: # Data from CSV or API data that didn't fit the above simple check (fallback to CSV mapping)
        print("Processing Qualys data (source: CSV or API fallback)...")
        qualys_col_map = { # Define standard internal names and potential CSV column names
            'IP_orig': ['IP', 'Host IP', 'IP Address'], 'QID_orig': ['QID', 'Plugin ID', 'ID', 'Qualys ID'],
            'Qualys_Title': ['Title', 'Vulnerability Title'], 'Qualys_Severity': ['Severity', 'Risk'], 
            'Qualys_CVSS': ['CVSS Base', 'CVSS', 'CVSS Score'], 'Qualys_Results': ['Results', 'Finding Details', 'Output'],
            'DNS Name': ['DNS Name', 'DNS', 'Hostname'], 'NetBIOS Name': ['NetBIOS Name', 'NetBIOS'],
            'OS': ['OS', 'Operating System']
        }
        qualys_df_intermediate = pd.DataFrame()
        actual_qualys_cols = {}
        for target_col, source_options in qualys_col_map.items():
            for source_col_name in source_options:
                if source_col_name in qualys_df_full.columns:
                    qualys_df_intermediate[target_col] = qualys_df_full[source_col_name]
                    actual_qualys_cols[target_col] = source_col_name
                    break
        
        if 'IP_orig' not in qualys_df_intermediate.columns or 'QID_orig' not in qualys_df_intermediate.columns:
            print("Error: Essential columns for IP or QID could not be mapped in Qualys data. Exiting.")
            print(f"Attempted mapping: {actual_qualys_cols}")
            print(f"Available columns in Qualys data: {list(qualys_df_full.columns)}")
            return
        
        print(f"Using Qualys source columns (mapped): {actual_qualys_cols}")
        qualys_df_cleaned = qualys_df_intermediate.copy() 
        qualys_df_cleaned.loc[:, 'Clean_IP'] = qualys_df_cleaned['IP_orig'].progress_apply(clean_qualys_ip_csv)
        qualys_df_cleaned.loc[:, 'Plugin_ID_Normalized'] = qualys_df_cleaned['QID_orig'].progress_apply(normalize_plugin_id)
        # Ensure 'QID' column holds the normalized ID for reporting consistency
        qualys_df_cleaned['QID'] = qualys_df_cleaned['Plugin_ID_Normalized']


    qualys_df_cleaned.dropna(subset=['Clean_IP', 'Plugin_ID_Normalized'], inplace=True)
    print(f"Qualys data cleaned: {qualys_df_cleaned.shape[0]} rows.")


    # Nessus Preprocessing
    print("Processing Nessus data...")
    nessus_col_map = {
        'Plugin ID_orig': ['Plugin ID', 'ID', 'Nessus ID'], 'Host_orig': ['Host', 'IP Address', 'Host IP', 'DNS Name'], 
        'Nessus_CVSS': ['CVSS', 'CVSS Base Score', 'Base Score'], 'Nessus_Risk': ['Risk', 'Severity'],
        'Nessus_Title': ['Name', 'Plugin Name', 'Title'], 'Nessus_Synopsis': ['Synopsis', 'Summary'], # Added Synopsis
        'Nessus_Results': ['Plugin Output', 'Output', 'Details'], 'Port': ['Port'] # Port is directly used
    }
    nessus_df_intermediate = pd.DataFrame()
    actual_nessus_cols = {}
    for target_col, source_options in nessus_col_map.items():
        for source_col_name in source_options:
            if source_col_name in nessus_df_full.columns:
                nessus_df_intermediate[target_col] = nessus_df_full[source_col_name]
                actual_nessus_cols[target_col] = source_col_name
                break
    if 'Host_orig' not in nessus_df_intermediate.columns or 'Plugin ID_orig' not in nessus_df_intermediate.columns:
        print("Error: Essential columns 'Host' or 'Plugin ID' could not be mapped in Nessus report. Exiting.")
        return

    print(f"Using Nessus columns (mapped): {actual_nessus_cols}")
    nessus_df_cleaned = nessus_df_intermediate.copy()
    nessus_df_cleaned.loc[:, 'Clean_Host_IP_Or_Name'] = nessus_df_cleaned['Host_orig'].progress_apply(clean_nessus_host)
    nessus_df_cleaned.loc[:, 'Plugin_ID_Normalized'] = nessus_df_cleaned['Plugin ID_orig'].progress_apply(normalize_plugin_id)
    # Ensure 'Plugin ID' column holds the original Nessus Plugin ID for reporting
    nessus_df_cleaned['Plugin ID'] = nessus_df_cleaned['Plugin ID_orig']


    nessus_df_cleaned.dropna(subset=['Clean_Host_IP_Or_Name', 'Plugin_ID_Normalized'], inplace=True)
    
    nessus_df_cleaned_ip_only = nessus_df_cleaned[nessus_df_cleaned['Clean_Host_IP_Or_Name'].progress_apply(is_ip_address)].copy()
    nessus_df_cleaned_ip_only.rename(columns={'Clean_Host_IP_Or_Name': 'Clean_Host_IP'}, inplace=True) 
    print(f"Nessus data cleaned (IPs only): {nessus_df_cleaned_ip_only.shape[0]} rows.")


    # --- 3. Merge Data ---
    print("Merging Qualys and Nessus data on IP and Plugin ID...")
    merged_df = pd.merge(
        qualys_df_cleaned,
        nessus_df_cleaned_ip_only, 
        left_on=['Clean_IP', 'Plugin_ID_Normalized'],
        right_on=['Clean_Host_IP', 'Plugin_ID_Normalized'],
        how='outer',
        suffixes=('_q', '_n') 
    )
    print(f"Initial merged data: {merged_df.shape[0]} rows.")

    # --- 4. Identify Matches and Differences ---
    print("Identifying matches and differences...")
    merged_df['Matched_IP'] = merged_df['Clean_IP'].fillna(merged_df['Clean_Host_IP'])
    
    qualys_report_cols_std = ['Qualys_Title', 'Qualys_Severity', 'Qualys_CVSS', 'Qualys_Results', 'DNS Name', 'NetBIOS Name', 'OS', 'QID']
    nessus_report_cols_std = ['Nessus_Title', 'Nessus_Risk', 'Nessus_CVSS', 'Nessus_Results', 'Port', 'Plugin ID', 'Nessus_Synopsis']

    final_cols_list = ['Matched_IP', 'Plugin_ID_Normalized'] + \
                      [col for col in qualys_report_cols_std if col in merged_df.columns] + \
                      [col for col in nessus_report_cols_std if col in merged_df.columns]
    
    final_cols_list = sorted(list(dict.fromkeys(final_cols_list))) 

    merged_df_final = merged_df[final_cols_list].copy()
    merged_df_final_sorted = merged_df_final.sort_values(by=['Matched_IP', 'Plugin_ID_Normalized']).reset_index(drop=True)
    print(f"Data for 'Potential_Matches_For_Review' sheet prepared: {merged_df_final_sorted.shape[0]} rows.")

    qualys_ips_unique = qualys_df_cleaned['Clean_IP'].dropna().unique()
    nessus_ips_scanned_unique = nessus_df_cleaned_ip_only['Clean_Host_IP'].dropna().unique() if 'Clean_Host_IP' in nessus_df_cleaned_ip_only else np.array([])
    
    ips_in_qualys_not_nessus = np.setdiff1d(qualys_ips_unique, nessus_ips_scanned_unique)
    cols_for_not_scanned_by_nessus = [c for c in ['Clean_IP', 'DNS Name', 'NetBIOS Name', 'OS'] if c in qualys_df_cleaned.columns]
    hosts_not_scanned_by_nessus_df = qualys_df_cleaned[qualys_df_cleaned['Clean_IP'].isin(ips_in_qualys_not_nessus)][
       cols_for_not_scanned_by_nessus
    ].drop_duplicates(subset=['Clean_IP']).reset_index(drop=True) if cols_for_not_scanned_by_nessus else pd.DataFrame()
    print(f"Hosts not scanned by Nessus: {hosts_not_scanned_by_nessus_df.shape[0]} rows.")

    ips_in_nessus_not_qualys = np.setdiff1d(nessus_ips_scanned_unique, qualys_ips_unique)
    cols_for_not_scanned_by_qualys = [c for c in ['Clean_Host_IP', 'Host_orig'] if c in nessus_df_cleaned_ip_only.columns] # Host_orig from Nessus mapping
    hosts_not_scanned_by_qualys_df = nessus_df_cleaned_ip_only[nessus_df_cleaned_ip_only['Clean_Host_IP'].isin(ips_in_nessus_not_qualys)][
        cols_for_not_scanned_by_qualys 
    ].drop_duplicates(subset=['Clean_Host_IP']).reset_index(drop=True) if cols_for_not_scanned_by_qualys else pd.DataFrame()
    if not hosts_not_scanned_by_qualys_df.empty:
        hosts_not_scanned_by_qualys_df.rename(columns={'Clean_Host_IP': 'IP', 'Host_orig': 'Nessus_Host_Identifier'}, inplace=True)
    print(f"Hosts not scanned by Qualys: {hosts_not_scanned_by_qualys_df.shape[0]} rows.")

    merged_df_final_sorted['Qualys_CVSS_Numeric'] = pd.to_numeric(merged_df_final_sorted.get('Qualys_CVSS'), errors='coerce')
    merged_df_final_sorted['Nessus_CVSS_Numeric'] = pd.to_numeric(merged_df_final_sorted.get('Nessus_CVSS'), errors='coerce')
    merged_df_final_sorted['Combined_CVSS'] = merged_df_final_sorted['Qualys_CVSS_Numeric'].fillna(merged_df_final_sorted['Nessus_CVSS_Numeric'])

    cvss_below_cutoff_df = merged_df_final_sorted[merged_df_final_sorted['Combined_CVSS'] < cvss_score_cutoff].reset_index(drop=True)
    cvss_above_cutoff_df = merged_df_final_sorted[merged_df_final_sorted['Combined_CVSS'] >= cvss_score_cutoff].reset_index(drop=True)
    no_cvss_score_df = merged_df_final_sorted[merged_df_final_sorted['Combined_CVSS'].isna()].reset_index(drop=True)
    print(f"CVSS scores below {cvss_score_cutoff}: {cvss_below_cutoff_df.shape[0]} rows.")
    print(f"CVSS scores >= {cvss_score_cutoff}: {cvss_above_cutoff_df.shape[0]} rows.")
    print(f"No CVSS score found: {no_cvss_score_df.shape[0]} rows.")

    unique_to_qualys_df = merged_df_final_sorted[
        merged_df_final_sorted['Qualys_Title'].notna() & merged_df_final_sorted['Nessus_Title'].isna()
    ].reset_index(drop=True)
    print(f"Vulnerabilities unique to Qualys: {unique_to_qualys_df.shape[0]} rows.")

    unique_to_nessus_df = merged_df_final_sorted[
        merged_df_final_sorted['Nessus_Title'].notna() & merged_df_final_sorted['Qualys_Title'].isna()
    ].reset_index(drop=True)
    print(f"Vulnerabilities unique to Nessus: {unique_to_nessus_df.shape[0]} rows.")

    # --- 5. Write to Excel ---
    print("Preparing to write reports to Excel...")
    
    file_part_counter = [0] 
    initial_output_filename = output_excel_path
    if len(merged_df_final_sorted) > MAX_ROWS_PER_FILE:
        file_part_counter[0] = 1
        initial_output_filename = f"{os.path.splitext(output_excel_path)[0]}_part{file_part_counter[0]}{os.path.splitext(output_excel_path)[1]}"
        print(f"Main data sheet is large. Initial output file will be: {initial_output_filename}")

    main_excel_writer = None
    main_writer_status = {'closed': True, 'path': None} 

    try:
        print(f"Creating initial Excel file: {initial_output_filename}")
        main_excel_writer = pd.ExcelWriter(initial_output_filename, engine='xlsxwriter')
        main_writer_status['closed'] = False
        main_writer_status['path'] = initial_output_filename
    except Exception as e:
        print(f"Error creating initial Excel writer for {initial_output_filename}: {e}. Cannot proceed.")
        return

    sheets_to_write_ordered_tuples = [
        ("Qualys_Report_Processed", qualys_df_cleaned), 
        ("Nessus_Report_Processed_IPs", nessus_df_cleaned_ip_only), 
        ("CVSS_Scores_Above_Cutoff", cvss_above_cutoff_df),
        ("CVSS_Scores_Below_Cutoff", cvss_below_cutoff_df),
        ("No_CVSS_Score_Found", no_cvss_score_df),
        ("Vulnerabilities_Unique_To_Qualys", unique_to_qualys_df),
        ("Vulnerabilities_Unique_To_Nessus", unique_to_nessus_df),
        ("Hosts_Not_Scanned_By_Nessus", hosts_not_scanned_by_nessus_df),
        ("Hosts_Not_Scanned_By_Qualys", hosts_not_scanned_by_qualys_df)
    ]
    sheets_to_write_ordered = [(name, df) for name, df in sheets_to_write_ordered_tuples if df is not None]


    print("Writing summary/smaller sheets...")
    for sheet_name, df_to_write in tqdm(sheets_to_write_ordered, desc="Writing summary sheets"):
        if main_writer_status['closed']: 
            print(f"Main writer was closed. Handling sheet '{sheet_name}' separately.")
            write_dataframe_to_excel_chunks(None, df_to_write, sheet_name, 
                                            main_writer_status, file_part_counter, output_excel_path)
        else:
            if len(df_to_write) > MAX_ROWS_PER_FILE:
                print(f"Summary sheet '{sheet_name}' is large ({len(df_to_write)} rows), will be chunked.")
                write_dataframe_to_excel_chunks(main_excel_writer, df_to_write, sheet_name, 
                                                main_writer_status, file_part_counter, output_excel_path)
            else: # df_to_write is not None and fits in one sheet
                if not df_to_write.empty:
                    print(f"Writing sheet '{sheet_name}' ({len(df_to_write)} rows) to {main_writer_status['path']}")
                    df_to_write.to_excel(main_excel_writer, sheet_name=sheet_name, index=False)
                else:
                    print(f"Sheet '{sheet_name}' is empty. Writing an empty sheet to {main_writer_status['path']}.")
                    pd.DataFrame().to_excel(main_excel_writer, sheet_name=sheet_name, index=False)

    print(f"Writing 'Potential_Matches_For_Review' (size: {len(merged_df_final_sorted)}) with chunking...")
    current_writer_for_main_sheet = main_excel_writer if not main_writer_status['closed'] else None
    write_dataframe_to_excel_chunks(
        current_writer_for_main_sheet,
        merged_df_final_sorted,
        "Potential_Matches_For_Review",
        main_writer_status, 
        file_part_counter,
        output_excel_path 
    )

    if main_excel_writer and not main_writer_status['closed'] and not main_excel_writer.closed: 
        print(f"Closing the initial Excel file: {main_writer_status['path']}")
        try:
            main_excel_writer.close()
        except Exception as e: 
            print(f"Error closing main Excel writer {main_writer_status['path']}: {e}")
    elif main_excel_writer and main_writer_status['closed']:
         print(f"Initial Excel writer ({initial_output_filename}) was already closed or handled by chunking.")
    
    print("\nScript finished.")
    if file_part_counter[0] == 0: 
        print(f"Output written to: {output_excel_path}")
    elif file_part_counter[0] == 1 and initial_output_filename.endswith("_part1.xlsx") and len(merged_df_final_sorted) <= MAX_ROWS_PER_FILE :
        print(f"Output written to: {initial_output_filename}") 
    else:
        print(f"Output split into multiple files. Files are named '{os.path.splitext(output_excel_path)[0]}_partX{os.path.splitext(output_excel_path)[1]}'.")
        print(f"Check files from '{os.path.splitext(output_excel_path)[0]}_part1...' up to '_part{file_part_counter[0]}...'")


if __name__ == '__main__':
    DEFAULT_QUALYS_CSV_FOR_TESTING = 'qualys_report.csv' 
    if not os.path.exists(DEFAULT_QUALYS_CSV_FOR_TESTING) and not (input(f"Qualys CSV '{DEFAULT_QUALYS_CSV_FOR_TESTING}' not found. Create dummy file? (yes/no): ").strip().lower() == 'no'):
        print(f"Creating dummy Qualys CSV for testing fallback: {DEFAULT_QUALYS_CSV_FOR_TESTING}")
        pd.DataFrame({
            'IP': [f'192.168.1.{i}' for i in range(1, 20)], 'QID': [1000 + i for i in range(1, 20)],
            'Title': [f'Qualys Vuln {i}' for i in range(1, 20)], 'Severity': [ (i % 5) + 1 for i in range(1,20)],
            'CVSS Base': [ ((i % 100)/10) for i in range(1,20)], 'Results': ['Result details' for _ in range(1,20)],
            'DNS Name': [f'host{i}.example.com' for i in range(1,20)], 'OS': ['Linux' if i % 2 == 0 else 'Windows' for i in range(1,20)]
        }).to_csv(DEFAULT_QUALYS_CSV_FOR_TESTING, index=False)

    if not os.path.exists(DEFAULT_NESSUS_CSV) and not (input(f"Nessus CSV '{DEFAULT_NESSUS_CSV}' not found. Create dummy file? (yes/no): ").strip().lower() == 'no'):
        print(f"Creating dummy Nessus CSV for testing: {DEFAULT_NESSUS_CSV}")
        pd.DataFrame({
            'Plugin ID': [1000 + i for i in range(5, 25)], 
            'Host': [f'192.168.1.{i}' if i%2==0 else f'asset{i}.domain.local' for i in range(5, 25)],
            'CVSS': [ ((i % 90)/10) for i in range(5,25)], 'Risk': ['High' if i > 15 else 'Medium' for i in range(5,25)],
            'Name': [f'Nessus Finding {i}' for i in range(5,25)], 'Synopsis': ['Synopsis here' for _ in range(5,25)],
            'Plugin Output': ['Nessus output details' for _ in range(5,25)], 'Port': [443 if i%3==0 else 80 for i in range(5,25)]
        }).to_csv(DEFAULT_NESSUS_CSV, index=False)
    main()
