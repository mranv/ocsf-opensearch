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
        logging.FileHandler('api_activity.log')
    ]
)
logger = logging.getLogger(__name__)

class APIActivityGenerator:
    def __init__(self):
        self.api_methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        self.api_endpoints = [
            "/api/v1/users",
            "/api/v1/resources",
            "/api/v2/data",
            "/api/v1/auth",
            "/api/v1/config",
            "/api/v2/metrics",
            "/api/v1/events",
            "/api/v2/analytics"
        ]
        self.status_codes = [
            (200, "Success", "OK"),
            (201, "Success", "Created"),
            (400, "Failure", "Bad Request"),
            (401, "Failure", "Unauthorized"),
            (403, "Failure", "Forbidden"),
            (404, "Failure", "Not Found"),
            (500, "Error", "Internal Server Error")
        ]
        self.users = [
            "api_user", "service_account", "admin", "system", 
            "app_client", "integration_user"
        ]
        self.api_versions = ["v1", "v2", "v3"]
        self.services = [
            "UserManagement",
            "ResourceService",
            "AuthService",
            "DataProcessor",
            "ConfigManager",
            "AnalyticsEngine"
        ]

    def generate_random_ip(self) -> str:
        return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))

    def generate_random_event(self) -> Dict[str, Any]:
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 60))
        method = random.choice(self.api_methods)
        endpoint = random.choice(self.api_endpoints)
        status_code, status, status_message = random.choice(self.status_codes)
        service = random.choice(self.services)
        
        event = {
            "class_uid": 6003,  # API Activity
            "class_name": "API Activity",
            "time": int(timestamp.timestamp() * 1000),
            "activity_id": 1,  # API Request
            "activity_name": "API_REQUEST",
            "api": {
                "request": {
                    "method": method,
                    "path": endpoint,
                    "version": random.choice(self.api_versions),
                    "headers": {
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {uuid.uuid4()}",
                        "X-Request-ID": str(uuid.uuid4())
                    }
                },
                "response": {
                    "status_code": status_code,
                    "message": status_message,
                    "headers": {
                        "Content-Type": "application/json",
                        "X-Response-Time": f"{random.randint(10, 500)}ms"
                    }
                },
                "service": {
                    "name": service,
                    "version": f"{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,9)}"
                }
            },
            "status": status,
            "status_id": 1 if status == "Success" else (2 if status == "Failure" else 3),
            "severity": "Info" if status == "Success" else "High",
            "severity_id": 1 if status == "Success" else 4,
            "src_endpoint": {
                "ip": self.generate_random_ip(),
                "hostname": f"client-{random.randint(1000, 9999)}",
                "port": random.randint(10000, 65535)
            },
            "dst_endpoint": {
                "ip": self.generate_random_ip(),
                "hostname": f"api-server-{random.randint(1, 10)}",
                "port": 443
            },
            "actor": {
                "user": {
                    "name": random.choice(self.users),
                    "uid": str(uuid.uuid4()),
                    "type": "Service Account"
                }
            },
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "API Gateway",
                    "vendor_name": "OCSF",
                    "version": "1.0.0"
                },
                "original_time": int(timestamp.timestamp() * 1000)
            },
            "unmapped": {
                "latency": random.randint(10, 500),
                "client_id": str(uuid.uuid4()),
                "api_key_id": str(uuid.uuid4())
            }
        }

        # Add request body for POST/PUT/PATCH methods
        if method in ["POST", "PUT", "PATCH"]:
            event["api"]["request"]["body_size"] = random.randint(100, 10000)

        # Add error details for failed requests
        if status != "Success":
            event["api"]["response"]["error_code"] = str(status_code)
            event["api"]["response"]["error_message"] = status_message
            event["api"]["response"]["error_details"] = f"Failed to {method.lower()} {endpoint}"

        return event

def main():
    parser = argparse.ArgumentParser(description='Generate and upload API activity events to OpenSearch')
    parser.add_argument('--host', default='15.206.174.96', help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--user', default='admin', help='OpenSearch username')
    parser.add_argument('--password', default='Anubhav@321', help='OpenSearch password')
    parser.add_argument('--events', type=int, default=10, help='Number of events to generate')
    parser.add_argument('--batch-size', type=int, default=5, help='Upload batch size')

    args = parser.parse_args()
    logger.info("Starting API activity event generation and upload")

    # Initialize OpenSearch client
    client = OpenSearch(
        hosts=[{'host': args.host, 'port': args.port}],
        http_auth=(args.user, args.password),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False
    )

    # Create index template
    template_name = "ocsf-1.1.0-6003-api_activity"
    template = {
        "index_patterns": ["ocsf-1.1.0-6003-api_activity-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1,
                "index.mapping.total_fields.limit": 10000
            },
            "mappings": {
                "properties": {
                    "class_uid": {"type": "long"},
                    "class_name": {"type": "keyword"},
                    "time": {"type": "date"},
                    "activity_id": {"type": "long"},
                    "activity_name": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "status_id": {"type": "long"},
                    "severity": {"type": "keyword"},
                    "severity_id": {"type": "long"},
                    "api": {
                        "properties": {
                            "request": {
                                "properties": {
                                    "method": {"type": "keyword"},
                                    "path": {"type": "keyword"},
                                    "version": {"type": "keyword"},
                                    "headers": {
                                        "type": "object",
                                        "enabled": True
                                    },
                                    "body_size": {"type": "long"}
                                }
                            },
                            "response": {
                                "properties": {
                                    "status_code": {"type": "integer"},
                                    "message": {"type": "keyword"},
                                    "headers": {
                                        "type": "object",
                                        "enabled": True
                                    },
                                    "error_code": {"type": "keyword"},
                                    "error_message": {"type": "keyword"},
                                    "error_details": {"type": "text"}
                                }
                            },
                            "service": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "version": {"type": "keyword"}
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
                                    "type": {"type": "keyword"}
                                }
                            }
                        }
                    },
                    "src_endpoint": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "hostname": {"type": "keyword"},
                            "port": {"type": "integer"}
                        }
                    },
                    "dst_endpoint": {
                        "properties": {
                            "ip": {"type": "ip"},
                            "hostname": {"type": "keyword"},
                            "port": {"type": "integer"}
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
    generator = APIActivityGenerator()
    events = [generator.generate_random_event() for _ in range(args.events)]

    # Upload in batches
    current_date = datetime.now().strftime("%Y.%m.%d")
    index_name = f"ocsf-1.1.0-6003-api_activity-{current_date}-000000"
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
