# HTTP Activity Data Processing Tools

This directory contains a collection of Python scripts for processing and converting HTTP access logs into OCSF-compliant formats for OpenSearch integration.

## Prerequisites

```bash
pip install opensearchpy pyarrow pandas user-agents urllib3
```

## Scripts Overview

### 1. Apache Log to Basic JSON (`apache-json.py`)

Converts raw Apache access logs to a basic JSON format.

```bash
python apache-json.py
```

- **Input**: `raw.log` (Apache combined log format)
- **Output**: `access_log_n.json`
- **Features**:
  - Simple parsing of IP, timestamp, request, status, bytes, referer, user-agent
  - Minimal processing, raw data preservation
  - Useful for initial data inspection

### 2. Apache Log to OCSF JSON (`apache-ocsf-json.py`)

Converts Apache logs to OCSF-compliant JSON with enriched metadata.

```bash
python apache-ocsf-json.py
```

- **Input**: `raw.log`
- **Output**: `parsed_logs.json`
- **Features**:
  - Full OCSF schema compliance
  - User agent parsing and enrichment
  - Geo-location placeholder
  - Event categorization
  - HTTP metadata extraction

### 3. JSON to OCSF Parquet (`json-ocsf.py`)

Transforms JSON logs into OCSF-compliant Parquet format.

```bash
python json-ocsf.py
```

- **Input**: `jso.log`
- **Output**: `result.parquet`
- **Features**:
  - OCSF schema mapping
  - HTTP method classification
  - Activity type identification
  - Columnar Parquet format optimized for analytics

### 4. OCSF OpenSearch Uploader (`sampledata.py`)

Uploads OCSF-formatted data to OpenSearch.

```bash
python sampledata.py --input parsed_logs.json [options]
```

- **Options**:
  - `--host`: OpenSearch host (default: 15.206.174.96)
  - `--port`: OpenSearch port (default: 9200)
  - `--user`: Username (default: admin)
  - `--password`: Password
  - `--secure`: Enable SSL verification
  - `--batch-size`: Upload batch size (default: 100)

- **Features**:
  - Batch processing
  - OCSF schema validation
  - Automatic index mapping
  - Error handling and retry logic
  - SSL/TLS support

## Workflow Example

1. Start with raw Apache logs:
   ```bash
   # Convert to basic JSON for inspection
   python apache-json.py
   
   # Convert to OCSF-compliant JSON
   python apache-ocsf-json.py
   
   # (Optional) Convert to Parquet
   python json-ocsf.py
   
   # Upload to OpenSearch
   python sampledata.py --input parsed_logs.json --host your-opensearch-host
   ```

## Data Format Examples

### Apache Combined Log Format (Input)
```
127.0.0.1 - - [10/Oct/2023:13:55:36 +0000] "GET /api/v1/status HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
```

### OCSF-Compliant JSON (Intermediate)
```json
{
  "class_uid": 4002,
  "class_name": "HTTP Activity",
  "activity_id": 1,
  "http_request": {
    "method": "GET",
    "url": {
      "full": "/api/v1/status"
    }
  },
  "time": 1696942536000
}
```

## Best Practices

1. Always validate input log formats
2. Monitor memory usage with large log files
3. Use batch processing for large datasets
4. Implement error handling for network operations
5. Keep SSL certificates updated for production

## Troubleshooting

- **Parser Errors**: Check log format matches expected pattern
- **Memory Issues**: Reduce batch size
- **Connection Errors**: Verify OpenSearch credentials and network
- **Schema Errors**: Validate OCSF compliance of output

## References

- [OCSF Schema](https://schema.ocsf.io/)
- [OpenSearch Documentation](https://opensearch.org/docs/latest/)
- [Apache Log Format](https://httpd.apache.org/docs/current/logs.html)
