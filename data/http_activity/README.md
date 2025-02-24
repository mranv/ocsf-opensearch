# HTTP Activity Generator

Generates and uploads OCSF-compliant HTTP activity events (class_uid: 4002) to OpenSearch.

## Prerequisites

```bash
pip install opensearchpy urllib3 user-agents
```

## Usage

```bash
python http_activity_uploader.py [options]
```

### Options
- `--host`: OpenSearch host (default: 15.206.174.96)
- `--port`: OpenSearch port (default: 9200)
- `--user`: Username (default: admin)
- `--password`: Password (default: Anubhav@321)
- `--events`: Number of events to generate (default: 10)
- `--batch-size`: Upload batch size (default: 5)

## Events Generated
- HTTP requests/responses
- User agent information
- Status codes and errors
- Request/response headers and body sizes