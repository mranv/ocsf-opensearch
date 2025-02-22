# OCSF Event Composer

Orchestrates the generation and upload of multiple OCSF event types to OpenSearch.

## Prerequisites

```bash
pip install -r requirements.txt
```

## Usage

```bash
python ocsf_composer.py [options]
```

### Options
- `--host`: OpenSearch host (default: 52.66.102.200)
- `--port`: OpenSearch port (default: 9200)
- `--user`: Username (default: admin)
- `--password`: Password (default: Anubhav@321)
- `--events-per-type`: Number of events per type (default: 10)
- `--batch-size`: Upload batch size (default: 100)

## Supported Event Types
- File System Activity (1001)
- Network Activity (4001)
- HTTP Activity (4002)
- DNS Activity (4003)
- Authentication (3002)
- API Activity (6003)
- And more...

## Adding New Generators
1. Create new generator class in appropriate directory
2. Add to generators_config in composer
3. Implement generate_random_event() method
4. Add appropriate index template