# Qualys-Nessus Vulnerability Matcher

This script automates the process of generating a Qualys vulnerability report, downloading it, and comparing it against a Nessus vulnerability report (in Excel format). The result is an Excel file with match analysis including Unique ID, IP, Port, CVE, QID, Vulnerability Status, and Reported Finding.

## Features

- Authenticates to the Qualys API and launches or fetches a vulnerability scan report.
- Downloads the report in CSV format and parses it correctly with all 44 expected columns.
- Compares vulnerabilities based on IP, Port, and CVE from Nessus and Qualys reports.
- Outputs results including:
  - UniqueID from Nessus
  - Reported Finding from Nessus
  - CVE ID
  - QID from Qualys
  - IP and Port
  - Vulnerability Status (renamed from "Vuln State")
  - Match status (Match or No Match)
- Saves results in an Excel file with three sheets:
  - Match Summary
  - Nessus Expanded (exploded by CVEs)
  - Qualys Expanded (exploded by CVEs)

## Usage

1. Run the script.
2. Enter Qualys credentials and Nessus file/sheet name.
3. Choose whether to generate a new Qualys report or use an existing one.
4. Provide Asset Group ID(s) or a host file for the report target.
5. Wait while the report is generated/downloaded.
6. Review the match results saved in `reports/nessus_vs_qualys_results.xlsx`.

## Requirements

- Python 3.7+
- `pandas`
- `openpyxl`
- `requests`

Install dependencies with:

```bash
pip install pandas openpyxl requests tqdm
```

## Notes

- Make sure the Nessus report is in `.xlsx` format and includes the necessary columns (`Unique ID`, `IP Address`, `Port`, `CVE`, `Reported Finding`).
- The Qualys report should be generated using a template that includes QID, CVE ID, and Vulnerability Status fields.
