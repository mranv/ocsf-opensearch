import json
import random
from datetime import datetime, timedelta
from opensearchpy import OpenSearch, helpers
import urllib3
import logging
import argparse
from typing import List, Dict, Any
import uuid

# Disable SSL warnings
urllib3.disable_warnings()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('account_changes.log')
    ]
)
logger = logging.getLogger(__name__)

class AccountChangeGenerator:
    def __init__(self):
        self.users = ["john.doe", "jane.smith", "admin", "root", "jenkins", "service.account", 
                     "developer", "analyst", "support", "manager"]
        self.actions = [
            ("create", 1), ("modify", 2), ("delete", 3), ("enable", 4), 
            ("disable", 5), ("lock", 6), ("unlock", 7), ("password_change", 8)
        ]
        self.groups = ["users", "admins", "developers", "operators", "support", "management"]
        self.status_codes = [
            ("success", 1), ("failure", 2), ("error", 3)
        ]
        self.auth_protocols = ["Local", "LDAP", "OAuth2", "SAML", "Kerberos"]
        self.domains = ["corp.local", "dev.local", "prod.local"]
        logger.info("Initialized AccountChangeGenerator with %d users and %d possible actions", 
                   len(self.users), len(self.actions))

    def generate_random_event(self) -> Dict[str, Any]:
        """Generate a random account change event"""
        action, action_id = random.choice(self.actions)
        status, status_id = random.choice(self.status_codes)
        actor_user = random.choice(self.users)
        target_user = random.choice(self.users)
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 60))
        
        event = {
            "class_uid": 3001,  # Account Change
            "class_name": "Account Change",
            "time": int(timestamp.timestamp() * 1000),
            "activity_id": action_id,
            "activity_name": action.upper(),
            "status_id": status_id,
            "status": status.upper(),
            "severity_id": 2 if status_id != 1 else 1,
            "severity": "Medium" if status_id != 1 else "Info",
            "actor": {
                "user": {
                    "name": actor_user,
                    "uid": str(uuid.uuid4()),
                    "type": "User",
                    "domain": random.choice(self.domains),
                    "groups": random.sample(self.groups, k=random.randint(1, 3))
                }
            },
            "target": {
                "user": {
                    "name": target_user,
                    "uid": str(uuid.uuid4()),
                    "type": "User",
                    "domain": random.choice(self.domains),
                    "groups": random.sample(self.groups, k=random.randint(1, 3))
                }
            },
            "auth_protocol": random.choice(self.auth_protocols),
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "Identity Management System",
                    "vendor_name": "OCSF",
                    "version": "1.0.0"
                },
                "original_time": int(timestamp.timestamp() * 1000)
            },
            "unmapped": {
                "session_id": str(uuid.uuid4()),
                "request_id": str(uuid.uuid4())
            }
        }

        # Add action-specific details
        if action == "password_change":
            event["password_change"] = {
                "enforced": random.choice([True, False]),
                "strength": random.randint(60, 100)
            }
        elif action in ["lock", "unlock"]:
            event["account_status"] = {
                "reason": "Multiple failed login attempts" if action == "lock" else "Administrative action",
                "duration": random.randint(300, 3600) if action == "lock" else 0
            }

        logger.debug("Generated event: %s -> %s (%s)", 
                    event['actor']['user']['name'],
                    event['target']['user']['name'],
                    event['activity_name'])
        return event

def main():
    parser = argparse.ArgumentParser(description='Generate and upload account change events to OpenSearch')
    parser.add_argument('--host', default='52.66.102.200', help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--user', default='admin', help='OpenSearch username')
    parser.add_argument('--password', default='Anubhav@321', help='OpenSearch password')
    parser.add_argument('--events', type=int, default=10, help='Number of events to generate')
    parser.add_argument('--batch-size', type=int, default=5, help='Upload batch size')

    args = parser.parse_args()
    logger.info("Starting account change event generation and upload")
    logger.info("Configuration: host=%s, events=%d, batch_size=%d", 
                args.host, args.events, args.batch_size)

    try:
        # Initialize OpenSearch client
        logger.info("Connecting to OpenSearch at %s:%d", args.host, args.port)
        client = OpenSearch(
            hosts=[{'host': args.host, 'port': args.port}],
            http_auth=(args.user, args.password),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False
        )

        # Verify connection
        cluster_info = client.info()
        logger.info("Successfully connected to OpenSearch cluster: %s", 
                   cluster_info.get('cluster_name', 'unknown'))

        # Create index template
        template_name = "ocsf-1.1.0-3001-account_change"
        logger.info("Creating/updating index template: %s", template_name)
        template = {
            "index_patterns": ["ocsf-1.1.0-3001-account_change-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1
                },
                "mappings": {
                    "properties": {
                        "actor": {
                            "properties": {
                                "user": {
                                    "properties": {
                                        "name": {"type": "keyword"},
                                        "uid": {"type": "keyword"},
                                        "type": {"type": "keyword"},
                                        "domain": {"type": "keyword"},
                                        "groups": {"type": "keyword"}
                                    }
                                }
                            }
                        },
                        "target": {
                            "properties": {
                                "user": {
                                    "properties": {
                                        "name": {"type": "keyword"},
                                        "uid": {"type": "keyword"},
                                        "type": {"type": "keyword"},
                                        "domain": {"type": "keyword"},
                                        "groups": {"type": "keyword"}
                                    }
                                }
                            }
                        },
                        "password_change": {
                            "properties": {
                                "enforced": {"type": "boolean"},
                                "strength": {"type": "integer"}
                            }
                        },
                        "account_status": {
                            "properties": {
                                "reason": {"type": "keyword"},
                                "duration": {"type": "integer"}
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

        # Initialize generator and start processing
        generator = AccountChangeGenerator()
        logger.info("Generating %d events...", args.events)
        
        events = []
        for i in range(args.events):
            event = generator.generate_random_event()
            events.append(event)
            logger.debug("Generated event %d/%d: %s", 
                        i + 1, args.events, event['activity_name'])

        # Upload in batches
        current_date = datetime.now().strftime("%Y.%m.%d")
        index_name = f"ocsf-1.1.0-3001-account_change-{current_date}-000000"
        logger.info("Uploading to index: %s", index_name)
        
        successful = 0
        failed = 0
        total_batches = (len(events) + args.batch_size - 1) // args.batch_size

        for i in range(0, len(events), args.batch_size):
            batch = events[i:i + args.batch_size]
            batch_num = (i // args.batch_size) + 1
            logger.info("Processing batch %d/%d (%d events)", 
                       batch_num, total_batches, len(batch))

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
                    logger.error("Batch %d: Failed items: %s", batch_num, failed_items)
                else:
                    logger.info("Batch %d: Successfully uploaded %d events", 
                              batch_num, success)
            except Exception as e:
                failed += len(batch)
                logger.error("Batch %d: Upload error: %s", batch_num, str(e))

        # Print final summary
        logger.info("=" * 50)
        logger.info("Upload Summary:")
        logger.info("Total events processed: %d", args.events)
        logger.info("Successfully uploaded: %d", successful)
        logger.info("Failed uploads: %d", failed)
        logger.info("Success rate: %.2f%%", (successful / args.events) * 100)
        logger.info("=" * 50)

    except Exception as e:
        logger.error("Fatal error: %s", str(e))
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Process interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error("Unexpected error: %s", str(e))
        sys.exit(1)
