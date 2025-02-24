# API Activity Generator

Generates and uploads OCSF-compliant API activity events (class_uid: 6003) to OpenSearch.

## Prerequisites

```bash
pip install opensearchpy urllib3
```

## Usage

```bash
python api_activity_uploader.py [options]
```

### Options
- `--host`: OpenSearch host (default: 15.206.174.96)
- `--port`: OpenSearch port (default: 9200)
- `--user`: Username (default: admin)
- `--password`: Password (default: Anubhav@321)
- `--events`: Number of events to generate (default: 10)
- `--batch-size`: Upload batch size (default: 5)

## Events Generated
- API requests/responses
- Different HTTP methods (GET, POST, PUT, etc.)
- Success/failure statuses
- Service information