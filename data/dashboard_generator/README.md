# OCSF Dashboard Generator

Generates and uploads OpenSearch dashboards for OCSF 1.1.0 data visualization.

## Prerequisites

```bash
pip install opensearchpy urllib3
```

## Usage

```bash
python ocsf_dashboard_generator.py [options]
```

### Options
- `--host`: OpenSearch host (default: 52.66.102.200)
- `--port`: OpenSearch port (default: 9200)
- `--user`: Username (default: admin)
- `--password`: Password (default: Anubhav@321)
- `--ndjson-template`: Path to NDJSON template file (optional)

## Features
- Creates OCSF 1.1.0 overview dashboard
- Generates HTTP Activity (4002) visualizations:
  - HTTP Methods distribution
  - Response Status Codes
  - Traffic patterns
  - Error rates
- Supports custom NDJSON template import
- Real-time dashboard updates

## Example NDJSON Template
```ndjson
{"attributes":{"title":"HTTP Methods","visState":"{\"type\":\"pie\"}"}}
{"attributes":{"title":"Status Codes","visState":"{\"type\":\"histogram\"}"}}
```
