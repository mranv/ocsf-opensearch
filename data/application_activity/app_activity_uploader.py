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

class ApplicationActivityGenerator:
    def __init__(self):
        self.applications = [
            ("CRM System", "Sales"),
            ("ERP System", "Operations"),
            ("HR Portal", "Human Resources"),
            ("Inventory Management", "Logistics"),
            ("Billing System", "Finance")
        ]
        self.actions = [
            ("Login", 1),
            ("Logout", 2),
            ("Create", 3),
            ("Update", 4),
            ("Delete", 5),
            ("Export", 6),
            ("Import", 7),
            ("Search", 8)
        ]
        self.users = [
            "john.doe", "jane.smith", "admin.user",
            "system.service", "app.user", "batch.process"
        ]
        self.status_types = [
            ("Success", 1),
            ("Failure", 2),
            ("Error", 3)
        ]

    def generate_random_event(self) -> Dict[str, Any]:
        app_name, app_category = random.choice(self.applications)
        action, action_id = random.choice(self.actions)
        status, status_id = random.choice(self.status_types)
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 60))
        
        event = {
            "class_uid": 6001,  # Application Activity
            "class_name": "Application Activity",
            "time": int(timestamp.timestamp() * 1000),
            "activity_id": action_id,
            "activity_name": action.upper(),
            "status": status,
            "status_id": status_id,
            "severity_id": 1 if status == "Success" else 2,
            "severity": "Info" if status == "Success" else "Medium",
            "application": {
                "name": app_name,
                "uid": str(uuid.uuid4()),
                "category": app_category,
                "version": f"{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,9)}"
            },
            "actor": {
                "user": {
                    "name": random.choice(self.users),
                    "uid": str(uuid.uuid4()),
                    "type": "User"
                }
            },
            "src_endpoint": {
                "ip": str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1))),
                "hostname": f"host-{random.randint(1000, 9999)}"
            },
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "Application Monitor",
                    "vendor_name": "OCSF",
                    "version": "1.0.0"
                },
                "original_time": int(timestamp.timestamp() * 1000)
            }
        }

        return event

def main():
    parser = argparse.ArgumentParser(description='Generate application activity events')
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
    template_name = "ocsf-1.1.0-6001-application_activity"
    template = {
        "index_patterns": ["ocsf-1.1.0-6001-application_activity-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "application": {
                        "properties": {
                            "name": {"type": "keyword"},
                            "uid": {"type": "keyword"},
                            "category": {"type": "keyword"},
                            "version": {"type": "keyword"}
                        }
                    },
                    "actor": {
                        "properties": {
                            "user": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "uid": {"type": "keyword"},
                                    "type": {"type": "keyword"}
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
        logger.info(f"Created index template: {template_name}")
    except Exception as e:
        logger.error(f"Failed to create template: {e}")

    # Generate and upload events
    generator = ApplicationActivityGenerator()
    events = [generator.generate_random_event() for _ in range(args.events)]
    
    current_date = datetime.now().strftime("%Y.%m.%d")
    index_name = f"ocsf-1.1.0-6001-application_activity-{current_date}-000000"
    
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
