# System Activity Generator

Generates and uploads OCSF-compliant system activity events (class_uid: 1003) to OpenSearch.

## Prerequisites

```bash
pip install opensearchpy urllib3
```

## Usage

```bash
python kernel_activity_uploader.py [options]
```

### Options
- `--host`: OpenSearch host (default: 52.66.102.200)
- `--port`: OpenSearch port (default: 9200)
- `--user`: Username (default: admin)
- `--password`: Password (default: Anubhav@321)
- `--events`: Number of events to generate (default: 10)
- `--batch-size`: Upload batch size (default: 5)

## Events Generated
- Kernel module operations
- System configuration changes
- Process activities
- System calls
- Capability changes