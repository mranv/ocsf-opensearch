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
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('detection_finding.log')
    ]
)
logger = logging.getLogger(__name__)

class DetectionFindingGenerator:
    def __init__(self):
        self.finding_types = [
            ("Malware Detected", 1),
            ("Suspicious Activity", 2),
            ("Policy Violation", 3),
            ("System Compromise", 4),
            ("Data Exfiltration", 5)
        ]
        self.severities = [
            ("Critical", 5),
            ("High", 4),
            ("Medium", 3),
            ("Low", 2),
            ("Info", 1)
        ]
        self.categories = [
            "MALWARE",
            "BACKDOOR",
            "CRYPTOMINER",
            "RANSOMWARE",
            "TROJAN",
            "SUSPICIOUS_BEHAVIOR",
            "LATERAL_MOVEMENT"
        ]
        self.statuses = [
            ("New", 1),
            ("In Progress", 2),
            ("Mitigated", 3),
            ("Resolved", 4)
        ]
        self.detection_sources = [
            "Antivirus",
            "IDS",
            "EDR",
            "SIEM",
            "Firewall",
            "Threat Intelligence"
        ]

    def generate_random_ip(self) -> str:
        return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))

    def generate_random_event(self) -> Dict[str, Any]:
        finding_type, type_id = random.choice(self.finding_types)
        severity, severity_id = random.choice(self.severities)
        status, status_id = random.choice(self.statuses)
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 60))
        
        event = {
            "class_uid": 2004,  # Detection Finding
            "class_name": "Detection Finding",
            "time": int(timestamp.timestamp() * 1000),
            "finding": {
                "uid": str(uuid.uuid4()),
                "type": finding_type,
                "type_id": type_id,
                "categories": random.sample(self.categories, k=random.randint(1, 3)),
                "title": f"{finding_type} on {self.generate_random_ip()}",
                "message": f"Detection system identified {finding_type.lower()} activity",
                "src_endpoint": {
                    "ip": self.generate_random_ip(),
                    "hostname": f"host-{random.randint(1000, 9999)}",
                    "processes": [{
                        "pid": random.randint(1000, 65535),
                        "name": random.choice(["chrome.exe", "svchost.exe", "explorer.exe", "cmd.exe"])
                    }]
                },
                "confidence": random.randint(1, 100)
            },
            "severity": severity,
            "severity_id": severity_id,
            "status": status,
            "status_id": status_id,
            "detection_source": {
                "name": random.choice(self.detection_sources),
                "uid": str(uuid.uuid4())
            },
            "detection": {
                "rule": {
                    "uid": str(uuid.uuid4()),
                    "name": f"Rule-{random.randint(1000, 9999)}",
                    "version": "1.0"
                },
                "type": "Signature Based",
                "type_id": 1
            },
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "Security Detection System",
                    "vendor_name": "OCSF",
                    "version": "1.0.0"
                },
                "original_time": int(timestamp.timestamp() * 1000)
            }
        }

        # Add threat intel data for high severity findings
        if severity_id >= 4:
            event["finding"]["threat_intel"] = {
                "indicators": [
                    {
                        "type": "ip",
                        "value": self.generate_random_ip(),
                        "confidence": random.randint(70, 100)
                    },
                    {
                        "type": "hash",
                        "value": uuid.uuid4().hex,
                        "confidence": random.randint(70, 100)
                    }
                ],
                "sources": [
                    {
                        "name": "ThreatIntel Provider",
                        "uid": str(uuid.uuid4())
                    }
                ]
            }

        return event

def main():
    parser = argparse.ArgumentParser(description='Generate and upload detection finding events to OpenSearch')
    parser.add_argument('--host', default='15.206.174.96', help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--user', default='admin', help='OpenSearch username')
    parser.add_argument('--password', default='Anubhav@321', help='OpenSearch password')
    parser.add_argument('--events', type=int, default=10, help='Number of events to generate')
    parser.add_argument('--batch-size', type=int, default=5, help='Upload batch size')

    args = parser.parse_args()
    logger.info("Starting detection finding event generation and upload")

    # Initialize OpenSearch client
    client = OpenSearch(
        hosts=[{'host': args.host, 'port': args.port}],
        http_auth=(args.user, args.password),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False
    )

    # Create index template
    template_name = "ocsf-1.1.0-2004-detection_finding"
    template = {
        "index_patterns": ["ocsf-1.1.0-2004-detection_finding-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "finding": {
                        "properties": {
                            "uid": {"type": "keyword"},
                            "type": {"type": "keyword"},
                            "type_id": {"type": "integer"},
                            "categories": {"type": "keyword"},
                            "title": {"type": "text"},
                            "message": {"type": "text"},
                            "confidence": {"type": "integer"},
                            "threat_intel": {
                                "properties": {
                                    "indicators": {
                                        "type": "nested",
                                        "properties": {
                                            "type": {"type": "keyword"},
                                            "value": {"type": "keyword"},
                                            "confidence": {"type": "integer"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    try:
        client.indices.put_template(name=template_name, body=template)
        logger.info(f"Successfully created index template: {template_name}")
    except Exception as e:
        logger.error(f"Failed to create index template: {e}")

    # Initialize generator and generate events
    generator = DetectionFindingGenerator()
    events = [generator.generate_random_event() for _ in range(args.events)]

    # Upload in batches
    current_date = datetime.now().strftime("%Y.%m.%d")
    index_name = f"ocsf-1.1.0-2004-detection_finding-{current_date}-000000"
    successful = 0
    failed = 0

    for i in range(0, len(events), args.batch_size):
        batch = events[i:i + args.batch_size]
        batch_num = (i // args.batch_size) + 1
        logger.info(f"Processing batch {batch_num}/{(len(events) + args.batch_size - 1) // args.batch_size}")
        
        actions = [
            {
                '_index': index_name,
                '_source': event
            }
            for event in batch
        ]

        try:
            success, failed_items = helpers.bulk(client, actions, stats_only=False, raise_on_error=False)
            successful += success
            if failed_items:
                failed += len(failed_items)
                logger.error(f"Failed items in batch {batch_num}: {failed_items}")
            logger.info(f"Batch {batch_num}: {success} successful, {len(failed_items) if failed_items else 0} failed")
        except Exception as e:
            logger.error(f"Bulk upload error in batch {batch_num}: {str(e)}")
            failed += len(batch)

    # Print summary
    logger.info("=" * 50)
    logger.info(f"Upload complete to index: {index_name}")
    logger.info(f"Total events processed: {args.events}")
    logger.info(f"Successfully uploaded: {successful}")
    logger.info(f"Failed uploads: {failed}")
    logger.info(f"Success rate: {(successful/args.events)*100:.2f}%")
    logger.info("=" * 50)

if __name__ == "__main__":
    main()
