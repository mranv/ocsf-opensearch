# DNS Activity Generator

Generates and uploads OCSF-compliant DNS activity events (class_uid: 4003) to OpenSearch.

## Prerequisites

```bash
pip install opensearchpy urllib3
```

## Usage

```bash
python dns_activity_uploader.py [options]
```

### Options
- `--host`: OpenSearch host (default: 15.206.174.96)
- `--port`: OpenSearch port (default: 9200)
- `--user`: Username (default: admin)
- `--password`: Password (default: Anubhav@321)
- `--events`: Number of events to generate (default: 10)
- `--batch-size`: Upload batch size (default: 5)

## Events Generated
- DNS queries
- Various record types (A, AAAA, MX, etc.)
- Query responses
- DNS error conditions