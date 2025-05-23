
# Qualys vs Nessus Vulnerability Matcher

This script compares vulnerabilities between Nessus and Qualys scan results based on matching IP, Port, and CVE values.

## 🔧 Features

- Automatic column detection based on common names (`IP`, `Port`, `CVEs`, etc.)
- Fallback to user prompt if detection fails
- CLI arguments for full control
- JSON config file support for reusable mappings
- Saves matched results in `reports/` folder

---

## 🖥️ Usage

### Basic
```bash
python qualys_nessus_match_cli_and_preset.py
```

### With CLI Arguments
```bash
python qualys_nessus_match_cli_and_preset.py \
  --nessus-file findings.xlsx \
  --qualys-file findings.xlsx \
  --nessus-sheet Master \
  --qualys-sheet Qualys \
  --output-dir reports/
```

### With Config File
```bash
python qualys_nessus_match_cli_and_preset.py --config config.json
```

---

## ⚙️ Sample `config.json`

```json
{
  "nessus_file": "vulnerability_data.xlsx",
  "qualys_file": "vulnerability_data.xlsx",
  "nessus_sheet": "Master",
  "qualys_sheet": "Qualys",
  "columns": {
    "nessus": {
      "ip": "Host",
      "port": "Port",
      "cve": "CVE List"
    },
    "qualys": {
      "ip": "IP Address",
      "port": "Port Number",
      "qid": "QID",
      "cve": "CVEs",
      "state": "Vuln State"
    }
  },
  "output_dir": "reports"
}
```

---

## 📦 Required Libraries

Install the dependencies using:

```bash
pip install pandas openpyxl
```

---

## 📁 Output

- Saved as: `reports/nessus_vs_qualys_results.xlsx`
- Contains:
  - Match results
  - Original Nessus and Qualys data

---

## 📝 Notes

- CVEs are exploded and matched one-by-one.
- Only IP:Port:CVE triplets are considered for matches.
- Use `--help` to see all CLI options.
