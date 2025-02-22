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
        logging.FileHandler('dns_activity.log')
    ]
)
logger = logging.getLogger(__name__)

class DNSActivityGenerator:
    def __init__(self):
        self.query_types = [
            ("A", 1), ("AAAA", 28), ("MX", 15), ("NS", 2),
            ("PTR", 12), ("CNAME", 5), ("TXT", 16), ("SOA", 6)
        ]
        self.domains = [
            "example.com", "test.org", "dev.local", "prod.company.com",
            "mail.example.com", "api.service.com", "cdn.site.net", "db.internal"
        ]
        self.responses = {
            "A": ["192.168.1.1", "10.0.0.1", "172.16.0.1", "203.0.113.1"],
            "AAAA": ["2001:db8::1", "2001:db8::2", "2001:db8::3", "2001:db8::4"],
            "MX": ["mail1.example.com", "mail2.example.com"],
            "NS": ["ns1.example.com", "ns2.example.com"],
            "PTR": ["host1.example.com", "host2.example.com"],
            "CNAME": ["www.example.com", "cdn.example.com"],
            "TXT": ["v=spf1 include:_spf.example.com ~all", "verification=abc123"],
            "SOA": ["ns1.example.com admin.example.com 2024012001 3600 900 604800 86400"]
        }
        self.statuses = [
            ("NOERROR", 1), ("NXDOMAIN", 2), ("SERVFAIL", 3),
            ("REFUSED", 4), ("FORMERR", 5)
        ]

    def generate_random_ip(self) -> str:
        return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))

    def generate_random_event(self) -> Dict[str, Any]:
        query_type, query_type_id = random.choice(self.query_types)
        status, status_id = random.choice(self.statuses)
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 60))
        domain = random.choice(self.domains)
        
        event = {
            "class_uid": 4003,  # DNS Activity
            "class_name": "DNS Activity",
            "time": int(timestamp.timestamp() * 1000),
            "activity_id": 1,  # DNS Query
            "activity_name": "DNS_QUERY",
            "status": status,
            "status_id": status_id,
            "severity_id": 1,
            "severity": "Informational",
            "dns_query": {
                "type": query_type,
                "type_id": query_type_id,
                "name": domain,
                "response_code": status,
                "response_code_id": status_id
            },
            "src_endpoint": {
                "ip": self.generate_random_ip(),
                "port": random.randint(1024, 65535),
                "hostname": f"client-{random.randint(1, 1000)}"
            },
            "dst_endpoint": {
                "ip": self.generate_random_ip(),
                "port": 53,
                "hostname": f"dns-server-{random.randint(1, 10)}"
            },
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "DNS Server",
                    "vendor_name": "OCSF",
                    "version": "1.0.0"
                },
                "original_time": int(timestamp.timestamp() * 1000)
            }
        }

        # Add response data if status is NOERROR
        if status == "NOERROR":
            event["dns_query"]["answers"] = []
            response_count = random.randint(1, 3)
            for _ in range(response_count):
                if query_type in self.responses:
                    answer = random.choice(self.responses[query_type])
                    event["dns_query"]["answers"].append({
                        "type": query_type,
                        "type_id": query_type_id,
                        "data": answer,
                        "ttl": random.randint(300, 86400)
                    })

        return event

def main():
    parser = argparse.ArgumentParser(description='Generate and upload DNS activity events to OpenSearch')
    parser.add_argument('--host', default='52.66.102.200', help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--user', default='admin', help='OpenSearch username')
    parser.add_argument('--password', default='Anubhav@321', help='OpenSearch password')
    parser.add_argument('--events', type=int, default=10, help='Number of events to generate')
    parser.add_argument('--batch-size', type=int, default=5, help='Upload batch size')

    args = parser.parse_args()
    logger.info("Starting DNS activity event generation and upload")

    # Initialize OpenSearch client
    client = OpenSearch(
        hosts=[{'host': args.host, 'port': args.port}],
        http_auth=(args.user, args.password),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False
    )

    # Create index template
    template_name = "ocsf-1.1.0-4003-dns_activity"
    template = {
        "index_patterns": ["ocsf-1.1.0-4003-dns_activity-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "dns_query": {
                        "properties": {
                            "type": {"type": "keyword"},
                            "type_id": {"type": "integer"},
                            "name": {"type": "keyword"},
                            "response_code": {"type": "keyword"},
                            "response_code_id": {"type": "integer"},
                            "answers": {
                                "type": "nested",
                                "properties": {
                                    "type": {"type": "keyword"},
                                    "type_id": {"type": "integer"},
                                    "data": {"type": "keyword"},
                                    "ttl": {"type": "integer"}
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
    generator = DNSActivityGenerator()
    events = [generator.generate_random_event() for _ in range(args.events)]

    # Upload in batches
    current_date = datetime.now().strftime("%Y.%m.%d")
    index_name = f"ocsf-1.1.0-4003-dns_activity-{current_date}-000000"
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
