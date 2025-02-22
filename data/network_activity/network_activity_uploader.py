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
        logging.FileHandler('network_activity.log')
    ]
)
logger = logging.getLogger(__name__)

class NetworkActivityGenerator:
    def __init__(self):
        self.protocols = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "FTP", "SMTP", "SNMP"]
        self.ports = {
            "HTTP": 80,
            "HTTPS": 443,
            "DNS": 53,
            "SSH": 22,
            "FTP": 21,
            "SMTP": 25,
            "SNMP": 161
        }
        self.directions = ["Inbound", "Outbound"]
        self.statuses = [("Success", 1), ("Failure", 2), ("Error", 3)]
        self.severities = [("Info", 1), ("Low", 2), ("Medium", 3), ("High", 4), ("Critical", 5)]

    def generate_random_ip(self) -> str:
        """Generate a random IPv4 address"""
        return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))

    def generate_random_event(self) -> Dict[str, Any]:
        """Generate a random network activity event"""
        protocol = random.choice(self.protocols)
        direction = random.choice(self.directions)
        status, status_id = random.choice(self.statuses)
        severity, severity_id = random.choice(self.severities)
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 60))
        
        src_ip = self.generate_random_ip()
        dst_ip = self.generate_random_ip()
        
        event = {
            "class_uid": 4001,
            "class_name": "Network Activity",
            "activity_id": random.randint(1, 5),
            "activity_name": f"{protocol} {direction}",
            "time": int(timestamp.timestamp() * 1000),
            "status": status,
            "status_id": status_id,
            "severity": severity,
            "severity_id": severity_id,
            "src_endpoint": {
                "ip": src_ip,
                "port": random.randint(1024, 65535) if direction == "Outbound" else self.ports.get(protocol, random.randint(1, 65535)),
                "hostname": f"host-{src_ip.replace('.', '-')}",
                "processes": [{
                    "name": f"{protocol.lower()}_client",
                    "pid": random.randint(1000, 9999)
                }]
            },
            "dst_endpoint": {
                "ip": dst_ip,
                "port": self.ports.get(protocol, random.randint(1, 65535)) if direction == "Outbound" else random.randint(1024, 65535),
                "hostname": f"host-{dst_ip.replace('.', '-')}",
                "processes": [{
                    "name": f"{protocol.lower()}_server",
                    "pid": random.randint(1000, 9999)
                }]
            },
            "protocol": protocol,
            "direction": direction,
            "traffic": {
                "bytes_in": random.randint(100, 1000000),
                "bytes_out": random.randint(100, 1000000),
                "packets_in": random.randint(1, 1000),
                "packets_out": random.randint(1, 1000)
            },
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "Network Monitor",
                    "vendor_name": "OCSF",
                    "version": "1.0.0"
                },
                "original_time": int(timestamp.timestamp() * 1000)
            },
            "observables": [
                {
                    "name": "network_session_id",
                    "value": str(uuid.uuid4()),
                    "type": "Session ID"
                }
            ]
        }

        if protocol in ["HTTP", "HTTPS"]:
            event["http"] = {
                "method": random.choice(["GET", "POST", "PUT", "DELETE"]),
                "response": {
                    "status_code": random.choice([200, 201, 400, 401, 403, 404, 500])
                }
            }

        return event

def main():
    parser = argparse.ArgumentParser(description='Generate and upload network activity events to OpenSearch')
    parser.add_argument('--host', default='52.66.102.200', help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--user', default='admin', help='OpenSearch username')
    parser.add_argument('--password', default='Anubhav@321', help='OpenSearch password')
    parser.add_argument('--events', type=int, default=10, help='Number of events to generate')
    parser.add_argument('--batch-size', type=int, default=5, help='Upload batch size')

    args = parser.parse_args()
    logger.info("Starting network activity event generation and upload")

    # Initialize OpenSearch client
    client = OpenSearch(
        hosts=[{'host': args.host, 'port': args.port}],
        http_auth=(args.user, args.password),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False
    )

    # Create index template
    template_name = "ocsf-1.1.0-4001-network_activity"
    template = {
        "index_patterns": ["ocsf-1.1.0-4001-network_activity-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1,
                "index.mapping.total_fields.limit": 2000
            },
            "mappings": {
                "properties": {
                    "src_endpoint": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "port": {"type": "integer"},
                            "hostname": {"type": "keyword"},
                            "processes": {
                                "type": "nested",
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "pid": {"type": "long"}
                                }
                            }
                        }
                    },
                    "dst_endpoint": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "port": {"type": "integer"},
                            "hostname": {"type": "keyword"},
                            "processes": {
                                "type": "nested",
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "pid": {"type": "long"}
                                }
                            }
                        }
                    },
                    "traffic": {
                        "properties": {
                            "bytes_in": {"type": "long"},
                            "bytes_out": {"type": "long"},
                            "packets_in": {"type": "long"},
                            "packets_out": {"type": "long"}
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

    # Initialize generator
    generator = NetworkActivityGenerator()

    # Generate events
    events = []
    for _ in range(args.events):
        event = generator.generate_random_event()
        events.append(event)

    # Upload in batches
    current_date = datetime.now().strftime("%Y.%m.%d")
    index_name = f"ocsf-1.1.0-4001-network_activity-{current_date}-000000"
    successful = 0
    failed = 0

    for i in range(0, len(events), args.batch_size):
        batch = events[i:i + args.batch_size]
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
                logger.error(f"Failed items: {failed_items}")
            logger.info(f"Batch uploaded: {success} successful, {len(failed_items) if failed_items else 0} failed")
        except Exception as e:
            logger.error(f"Bulk upload error: {str(e)}")
            failed += len(batch)

    logger.info(f"Upload complete: {successful} successful, {failed} failed")
    logger.info(f"Events uploaded to index: {index_name}")

if __name__ == "__main__":
    main()
