import json
import random
from datetime import datetime, timedelta
from opensearchpy import OpenSearch, helpers
import urllib3
import logging
import argparse
from typing import Dict, Any
import uuid
import ipaddress

# Disable SSL warnings
urllib3.disable_warnings()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityFindingGenerator:
    def __init__(self):
        self.finding_types = [
            ("Intrusion Attempt", 1),
            ("Malware Detection", 2),
            ("Data Leak", 3),
            ("Policy Violation", 4),
            ("Configuration Issue", 5)
        ]
        self.severities = [
            ("Critical", 5),
            ("High", 4),
            ("Medium", 3),
            ("Low", 2),
            ("Info", 1)
        ]
        self.categories = [
            "ACCESS_CONTROL",
            "NETWORK_SECURITY",
            "DATA_PROTECTION",
            "ENDPOINT_SECURITY",
            "CONFIGURATION"
        ]
        self.sources = [
            "IDS",
            "Firewall",
            "EDR",
            "SIEM",
            "Security Scanner"
        ]

    def generate_random_event(self) -> Dict[str, Any]:
        finding_type, type_id = random.choice(self.finding_types)
        severity, severity_id = random.choice(self.severities)
        
        # Ensure consistent timestamp format
        current_time = datetime.now()
        end_date = datetime(2025, 2, 22)  # Set fixed end date
        time_diff = (end_date - current_time).total_seconds()
        random_seconds = random.uniform(0, time_diff)
        timestamp = current_time + timedelta(seconds=random_seconds)
        epoch_ms = int(timestamp.timestamp() * 1000)
        
        event = {
            "class_uid": 2001,
            "class_name": "Security Finding",
            "time": epoch_ms,  # Use epoch milliseconds
            "finding": {
                "uid": str(uuid.uuid4()),
                "title": f"{finding_type} detected",
                "type": finding_type,
                "type_id": type_id,
                "categories": random.sample(self.categories, k=random.randint(1, 3)),
                "message": f"Security system detected {finding_type.lower()}",
                "src_endpoint": {
                    "ip": str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1))),
                    "hostname": f"host-{random.randint(1000, 9999)}"
                }
            },
            "severity": severity,
            "severity_id": severity_id,
            "status": "New",
            "status_id": 1,
            "detection_source": {
                "name": random.choice(self.sources),
                "uid": str(uuid.uuid4())
            },
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "Security Monitor",
                    "vendor_name": "OCSF",
                    "version": "1.0.0"
                },
                "original_time": epoch_ms,  # Use same epoch milliseconds
                "created_time": epoch_ms    # Add created_time in epoch milliseconds
            }
        }

        if severity_id >= 4:
            event["finding"]["risk_score"] = random.randint(70, 100)

        return event

def main():
    parser = argparse.ArgumentParser(description='Generate security finding events')
    parser.add_argument('--host', default='15.206.174.96', help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--user', default='admin', help='OpenSearch username')
    parser.add_argument('--password', default='Anubhav@321', help='OpenSearch password')
    parser.add_argument('--events', type=int, default=10, help='Number of events to generate')
    parser.add_argument('--batch-size', type=int, default=5, help='Upload batch size')

    args = parser.parse_args()

    # Initialize OpenSearch client
    client = OpenSearch(
        hosts=[{'host': args.host, 'port': args.port}],
        http_auth=(args.user, args.password),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False
    )

    # Create index template
    template_name = "ocsf-1.1.0-2001-security_finding"
    template = {
        "index_patterns": ["ocsf-1.1.0-2001-security_finding-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "time": {
                        "type": "date",
                        "format": "epoch_millis||strict_date_optional_time"
                    },
                    "metadata": {
                        "properties": {
                            "original_time": {
                                "type": "date",
                                "format": "epoch_millis||strict_date_optional_time"
                            },
                            "created_time": {
                                "type": "date",
                                "format": "epoch_millis||strict_date_optional_time"
                            }
                        }
                    },
                    "finding": {
                        "properties": {
                            "uid": {"type": "keyword"},
                            "title": {"type": "text"},
                            "type": {"type": "keyword"},
                            "type_id": {"type": "integer"},
                            "categories": {"type": "keyword"},
                            "message": {"type": "text"},
                            "risk_score": {"type": "integer"},
                            "src_endpoint": {
                                "properties": {
                                    "ip": {"type": "ip"},
                                    "hostname": {"type": "keyword"}
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    try:
        # Delete existing template if exists
        client.indices.delete_template(name=template_name, ignore=[404])
        
        # Create new template
        client.indices.put_template(name=template_name, body=template)
        logger.info(f"Created index template: {template_name}")

        # Delete existing index if exists
        current_date = "2025.02.22"  # Use fixed date
        index_name = f"ocsf-1.1.0-2001-security_finding-{current_date}-000000"
        client.indices.delete(index=index_name, ignore=[404])
        
    except Exception as e:
        logger.error(f"Failed to create template: {e}")

    # Generate and upload events
    generator = SecurityFindingGenerator()
    events = [generator.generate_random_event() for _ in range(args.events)]
    
    successful = 0
    failed = 0

    for i in range(0, len(events), args.batch_size):
        batch = events[i:i + args.batch_size]
        actions = [{'_index': index_name, '_source': event} for event in batch]

        try:
            success, failed_items = helpers.bulk(client, actions, stats_only=False, raise_on_error=False)
            successful += success
            if failed_items:
                failed += len(failed_items)
        except Exception as e:
            logger.error(f"Upload error: {str(e)}")
            failed += len(batch)

    logger.info(f"Upload complete: {successful} successful, {failed} failed")

if __name__ == "__main__":
    main()
