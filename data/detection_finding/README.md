# Detection Finding Generator

Generates and uploads OCSF-compliant detection finding events (class_uid: 2004) to OpenSearch.

## Prerequisites

```bash
pip install opensearchpy urllib3
```

## Usage

```bash
python detection_finding_uploader.py [options]
```

### Options
- `--host`: OpenSearch host (default: 15.206.174.96)
- `--port`: OpenSearch port (default: 9200)
- `--user`: Username (default: admin)
- `--password`: Password (default: Anubhav@321)
- `--events`: Number of events to generate (default: 10)
- `--batch-size`: Upload batch size (default: 5)

## Events Generated
- Malware detections
- Suspicious activities
- System compromises
- Policy violations
- Threat intelligence data