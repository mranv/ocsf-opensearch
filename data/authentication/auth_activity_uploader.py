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
        logging.FileHandler('authentication.log')
    ]
)
logger = logging.getLogger(__name__)

class AuthenticationGenerator:
    def __init__(self):
        self.auth_types = [
            ("Password", 1),
            ("Multi-Factor", 2),
            ("Certificate", 3),
            ("Token", 4),
            ("SSO", 5),
            ("Biometric", 6)
        ]
        self.auth_protocols = [
            ("LDAP", 1),
            ("Kerberos", 2),
            ("SAML", 3),
            ("OAuth", 4),
            ("Local", 5),
            ("RADIUS", 6)
        ]
        self.users = [
            "john.doe", "jane.smith", "admin", "service.account",
            "developer1", "analyst2", "support.user", "system.admin"
        ]
        self.statuses = [
            ("Success", 1),
            ("Failure", 2, ["Invalid Credentials", "Account Locked", "Password Expired", "Invalid Token"]),
            ("Error", 3, ["Service Unavailable", "Network Error", "Timeout"])
        ]
        self.user_types = ["User", "Service Account", "System Account", "Administrator"]
        self.domains = ["corp.local", "dev.domain", "prod.internal"]
        self.applications = ["VPN", "Web Portal", "Email", "Database", "File Server", "Cloud Service"]
        self.mfa_types = ["SMS", "Email", "Authenticator App", "Hardware Token", "Biometric"]

    def generate_random_ip(self) -> str:
        return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))

    def generate_random_event(self) -> Dict[str, Any]:
        auth_type, auth_type_id = random.choice(self.auth_types)
        protocol, protocol_id = random.choice(self.auth_protocols)
        user = random.choice(self.users)
        status_info = random.choice(self.statuses)
        status, status_id = status_info[0], status_info[1]
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 60))

        event = {
            "class_uid": 3002,  # Authentication
            "class_name": "Authentication",
            "time": int(timestamp.timestamp() * 1000),
            "activity_id": 1,  # Authentication attempt
            "activity_name": "AUTH_ATTEMPT",
            "status": status,
            "status_id": status_id,
            "severity_id": 2 if status != "Success" else 1,
            "severity": "Medium" if status != "Success" else "Info",
            "auth_protocol": protocol,
            "auth_protocol_id": protocol_id,
            "authentication": {
                "type": auth_type,
                "type_id": auth_type_id,
                "session_id": str(uuid.uuid4())
            },
            "actor": {
                "user": {
                    "name": user,
                    "uid": str(uuid.uuid4()),
                    "type": random.choice(self.user_types),
                    "domain": random.choice(self.domains)
                }
            },
            "src_endpoint": {
                "ip": self.generate_random_ip(),
                "hostname": f"host-{random.randint(1000, 9999)}",
                "port": random.randint(1024, 65535)
            },
            "dst_endpoint": {
                "ip": self.generate_random_ip(),
                "hostname": f"auth-server-{random.randint(1, 5)}",
                "port": random.choice([389, 443, 636, 1812])  # Common auth ports
            },
            "application": {
                "name": random.choice(self.applications),
                "uid": str(uuid.uuid4())
            },
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "Authentication Service",
                    "vendor_name": "OCSF",
                    "version": "1.0.0"
                },
                "original_time": int(timestamp.timestamp() * 1000)
            }
        }

        # Add failure/error details
        if status != "Success":
            event["message"] = random.choice(status_info[2])
            event["authentication"]["failure_code"] = f"AUTH_{status.upper()}_{random.randint(1000, 9999)}"

        # Add MFA details for multi-factor authentication
        if auth_type == "Multi-Factor":
            event["authentication"]["mfa"] = {
                "type": random.choice(self.mfa_types),
                "success": random.choice([True, False]),
                "attempt": random.randint(1, 3)
            }

        return event

def main():
    parser = argparse.ArgumentParser(description='Generate and upload authentication events to OpenSearch')
    parser.add_argument('--host', default='52.66.102.200', help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--user', default='admin', help='OpenSearch username')
    parser.add_argument('--password', default='Anubhav@321', help='OpenSearch password')
    parser.add_argument('--events', type=int, default=10, help='Number of events to generate')
    parser.add_argument('--batch-size', type=int, default=5, help='Upload batch size')

    args = parser.parse_args()
    logger.info("Starting authentication event generation and upload")

    # Initialize OpenSearch client
    client = OpenSearch(
        hosts=[{'host': args.host, 'port': args.port}],
        http_auth=(args.user, args.password),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False
    )

    # Create index template
    template_name = "ocsf-1.1.0-3002-authentication"
    template = {
        "index_patterns": ["ocsf-1.1.0-3002-authentication-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "authentication": {
                        "properties": {
                            "type": {"type": "keyword"},
                            "type_id": {"type": "integer"},
                            "session_id": {"type": "keyword"},
                            "failure_code": {"type": "keyword"},
                            "mfa": {
                                "properties": {
                                    "type": {"type": "keyword"},
                                    "success": {"type": "boolean"},
                                    "attempt": {"type": "integer"}
                                }
                            }
                        }
                    },
                    "actor": {
                        "properties": {
                            "user": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "uid": {"type": "keyword"},
                                    "type": {"type": "keyword"},
                                    "domain": {"type": "keyword"}
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
    generator = AuthenticationGenerator()
    events = [generator.generate_random_event() for _ in range(args.events)]

    # Upload in batches
    current_date = datetime.now().strftime("%Y.%m.%d")
    index_name = f"ocsf-1.1.0-3002-authentication-{current_date}-000000"
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
