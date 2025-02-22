
# HTTP Activity Data Processing

This directory contains scripts to process HTTP access logs into various formats including JSON and OCSF-compliant Parquet files.

## Prerequisites

```bash
pip install pyarrow pandas user-agents
```

## Scripts

### 1. Basic JSON Conversion
Converts Apache logs to simple JSON format:

```bash
python apache-json.py
```
Input: `raw.log`
Output: `access_log_n.json`

### 2. OCSF-Compliant JSON 
Converts Apache logs to OCSF-compliant JSON with extended metadata:

```bash
python apache-ocsf-json.py
```
Input: `raw.log`
Output: `parsed_logs.json`

### 3. OCSF Parquet Conversion
Converts JSON data to OCSF-compliant Parquet format:

```bash
python json-ocsf.py
```
Input: `jso.log`
Output: `result.parquet`

## Log File Structure

- `raw.log`: Raw Apache access logs
- `apache_logs.log`: Sample Apache logs for testing
- Generated files will be placed in the same directory

## Notes

- Scripts expect input files to be in standard Apache combined log format
- Ensure you have read/write permissions in the directory
- Check script headers for specific input format requirements
