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
        logging.FileHandler('compliance_finding.log')
    ]
)
logger = logging.getLogger(__name__)

class ComplianceFindingGenerator:
    def __init__(self):
        self.compliance_frameworks = [
            ("PCI DSS", "Payment Card Industry Data Security Standard", ["3.2.1", "4.1", "8.2", "10.2"]),
            ("HIPAA", "Health Insurance Portability and Accountability Act", ["Privacy Rule", "Security Rule", "Enforcement Rule"]),
            ("SOX", "Sarbanes-Oxley Act", ["Section 302", "Section 404", "Section 409"]),
            ("GDPR", "General Data Protection Regulation", ["Article 5", "Article 17", "Article 32"]),
            ("ISO 27001", "Information Security Management", ["A.5", "A.9", "A.12", "A.14"]),
            ("NIST 800-53", "Security and Privacy Controls", ["AC-2", "AU-2", "CM-6", "SC-7"])
        ]
        
        self.severities = [
            ("Critical", 5),
            ("High", 4),
            ("Medium", 3),
            ("Low", 2),
            ("Info", 1)
        ]
        
        self.finding_types = [
            "Configuration Issue",
            "Missing Control",
            "Policy Violation",
            "Access Control Issue",
            "Encryption Issue",
            "Audit Log Issue"
        ]
        
        self.resources = [
            {"type": "Database", "names": ["prod-db", "user-db", "auth-db"]},
            {"type": "Server", "names": ["web-server", "app-server", "auth-server"]},
            {"type": "Network", "names": ["internal-net", "dmz", "backend-net"]},
            {"type": "Application", "names": ["payment-app", "crm-system", "hr-portal"]},
            {"type": "Storage", "names": ["user-data", "logs-storage", "backup-storage"]}
        ]

    def generate_random_event(self) -> Dict[str, Any]:
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 60))
        framework = random.choice(self.compliance_frameworks)
        severity, severity_id = random.choice(self.severities)
        resource_type = random.choice(self.resources)
        
        event = {
            "class_uid": 2003,  # Compliance Finding
            "class_name": "Compliance Finding",
            "time": int(timestamp.timestamp() * 1000),
            "finding": {
                "uid": str(uuid.uuid4()),
                "title": f"{framework[0]} Compliance Issue - {random.choice(self.finding_types)}",
                "type": random.choice(self.finding_types),
                "compliance": {
                    "framework": {
                        "name": framework[0],
                        "version": f"{random.randint(1,3)}.{random.randint(0,9)}",
                        "description": framework[1]
                    },
                    "requirement": {
                        "id": random.choice(framework[2]),
                        "description": f"Compliance requirement for {framework[0]}"
                    }
                },
                "resources": [{
                    "type": resource_type["type"],
                    "name": random.choice(resource_type["names"]),
                    "uid": str(uuid.uuid4())
                }],
                "message": f"Found non-compliance with {framework[0]} requirements",
                "remediation": {
                    "description": f"Implement required controls for {framework[0]} compliance",
                    "deadline": int((datetime.now() + timedelta(days=random.randint(1, 30))).timestamp() * 1000)
                }
            },
            "severity": severity,
            "severity_id": severity_id,
            "status": "New",
            "status_id": 1,
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "Compliance Scanner",
                    "vendor_name": "OCSF",
                    "version": "1.0.0"
                },
                "original_time": int(timestamp.timestamp() * 1000)
            }
        }

        # Add risk score for high severity findings
        if severity_id >= 4:
            event["finding"]["risk_score"] = random.randint(70, 100)
            event["finding"]["risk_level"] = "High"
        
        return event

def main():
    parser = argparse.ArgumentParser(description='Generate and upload compliance finding events to OpenSearch')
    parser.add_argument('--host', default='15.206.174.96', help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--user', default='admin', help='OpenSearch username')
    parser.add_argument('--password', default='Anubhav@321', help='OpenSearch password')
    parser.add_argument('--events', type=int, default=10, help='Number of events to generate')
    parser.add_argument('--batch-size', type=int, default=5, help='Upload batch size')

    args = parser.parse_args()
    logger.info("Starting compliance finding event generation and upload")

    # Initialize OpenSearch client and create template
    client = OpenSearch(
        hosts=[{'host': args.host, 'port': args.port}],
        http_auth=(args.user, args.password),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False
    )

    # Create index template
    template_name = "ocsf-1.1.0-2003-compliance_finding"
    template = {
        "index_patterns": ["ocsf-1.1.0-2003-compliance_finding-*"],
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
                            "title": {"type": "text"},
                            "type": {"type": "keyword"},
                            "compliance": {
                                "properties": {
                                    "framework": {
                                        "properties": {
                                            "name": {"type": "keyword"},
                                            "version": {"type": "keyword"},
                                            "description": {"type": "text"}
                                        }
                                    },
                                    "requirement": {
                                        "properties": {
                                            "id": {"type": "keyword"},
                                            "description": {"type": "text"}
                                        }
                                    }
                                }
                            },
                            "resources": {
                                "type": "nested",
                                "properties": {
                                    "type": {"type": "keyword"},
                                    "name": {"type": "keyword"},
                                    "uid": {"type": "keyword"}
                                }
                            },
                            "risk_score": {"type": "integer"},
                            "risk_level": {"type": "keyword"},
                            "remediation": {
                                "properties": {
                                    "description": {"type": "text"},
                                    "deadline": {"type": "date"}
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
        return

    # Generate and upload events
    generator = ComplianceFindingGenerator()
    events = [generator.generate_random_event() for _ in range(args.events)]

    # Upload in batches
    current_date = datetime.now().strftime("%Y.%m.%d")
    index_name = f"ocsf-1.1.0-2003-compliance_finding-{current_date}-000000"
    successful = 0
    failed = 0

    for i in range(0, len(events), args.batch_size):
        batch = events[i:i + args.batch_size]
        batch_num = (i // args.batch_size) + 1
        logger.info(f"Processing batch {batch_num}")
        
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
