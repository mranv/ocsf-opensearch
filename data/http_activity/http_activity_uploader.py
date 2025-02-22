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
from user_agents import parse

# Disable SSL warnings
urllib3.disable_warnings()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('http_activity.log')
    ]
)
logger = logging.getLogger(__name__)

class HTTPActivityGenerator:
    def __init__(self):
        self.http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
        self.status_codes = [
            (200, "Success", "OK"),
            (201, "Success", "Created"),
            (301, "Redirect", "Moved Permanently"),
            (302, "Redirect", "Found"),
            (400, "Client Error", "Bad Request"),
            (401, "Client Error", "Unauthorized"),
            (403, "Client Error", "Forbidden"),
            (404, "Client Error", "Not Found"),
            (500, "Server Error", "Internal Server Error"),
            (503, "Server Error", "Service Unavailable")
        ]
        self.paths = [
            "/api/v1/users",
            "/login",
            "/assets/images",
            "/products",
            "/cart",
            "/checkout",
            "/admin",
            "/docs",
            "/health"
        ]
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "curl/7.64.1",
            "PostmanRuntime/7.28.0",
            "python-requests/2.26.0"
        ]
        self.content_types = [
            "application/json",
            "text/html",
            "application/xml",
            "text/plain",
            "application/x-www-form-urlencoded"
        ]
        self.protocols = ["HTTP/1.1", "HTTP/2.0"]

    def generate_random_ip(self) -> str:
        return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))

    def generate_random_event(self) -> Dict[str, Any]:
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 60))
        method = random.choice(self.http_methods)
        status_code, status_type, status_message = random.choice(self.status_codes)
        path = random.choice(self.paths)
        user_agent = random.choice(self.user_agents)
        ua_info = parse(user_agent)
        
        event = {
            "class_uid": 4002,  # HTTP Activity
            "class_name": "HTTP Activity",
            "time": int(timestamp.timestamp() * 1000),
            "activity_id": 1,  # HTTP Request
            "activity_name": "HTTP_REQUEST",
            "status": status_type,
            "status_id": 1 if status_code < 400 else (2 if status_code < 500 else 3),
            "severity": "Info" if status_code < 400 else ("Medium" if status_code < 500 else "High"),
            "severity_id": 1 if status_code < 400 else (3 if status_code < 500 else 4),
            "src_endpoint": {
                "ip": self.generate_random_ip(),
                "port": random.randint(10000, 65535),
                "geo": {
                    "country": "United States",
                    "country_code": "US",
                    "city": "New York",
                    "location": {
                        "lat": 40.7128,
                        "lon": -74.0060
                    }
                }
            },
            "dst_endpoint": {
                "ip": self.generate_random_ip(),
                "port": 443,
                "hostname": "api.example.com"
            },
            "http_request": {
                "method": method,
                "url": {
                    "path": path,
                    "full": f"https://api.example.com{path}",
                    "query": "page=1&limit=10" if "api" in path else None
                },
                "headers": {
                    "user-agent": user_agent,
                    "content-type": random.choice(self.content_types),
                    "accept": "*/*"
                },
                "version": random.choice(self.protocols),
                "bytes": random.randint(100, 1000) if method in ["POST", "PUT", "PATCH"] else 0
            },
            "http_response": {
                "status_code": status_code,
                "message": status_message,
                "headers": {
                    "content-type": random.choice(self.content_types),
                    "server": "nginx/1.19.0"
                },
                "bytes": random.randint(100, 10000)
            },
            "user_agent": {
                "original": user_agent,
                "device": {
                    "name": ua_info.device.family,
                    "type": "Mobile" if ua_info.is_mobile else "Desktop"
                },
                "browser": {
                    "name": ua_info.browser.family,
                    "version": str(ua_info.browser.version[0])
                },
                "os": {
                    "name": ua_info.os.family,
                    "version": str(ua_info.os.version[0] if ua_info.os.version else "")
                }
            },
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "Web Server",
                    "vendor_name": "OCSF",
                    "version": "1.0.0"
                },
                "original_time": int(timestamp.timestamp() * 1000)
            }
        }

        # Add specific details for certain requests
        if method in ["POST", "PUT", "PATCH"]:
            event["http_request"]["content_type"] = random.choice(self.content_types)
        
        # Add error details for failed requests
        if status_code >= 400:
            event["error"] = {
                "code": str(status_code),
                "message": status_message,
                "details": f"Failed to {method} {path}"
            }

        return event

def main():
    parser = argparse.ArgumentParser(description='Generate and upload HTTP activity events to OpenSearch')
    parser.add_argument('--host', default='52.66.102.200', help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--user', default='admin', help='OpenSearch username')
    parser.add_argument('--password', default='Anubhav@321', help='OpenSearch password')
    parser.add_argument('--events', type=int, default=10, help='Number of events to generate')
    parser.add_argument('--batch-size', type=int, default=5, help='Upload batch size')

    args = parser.parse_args()
    logger.info("Starting HTTP activity event generation and upload")

    # Initialize OpenSearch client
    client = OpenSearch(
        hosts=[{'host': args.host, 'port': args.port}],
        http_auth=(args.user, args.password),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False
    )

    # Create index template
    template_name = "ocsf-1.1.0-4002-http_activity"
    template = {
        "index_patterns": ["ocsf-1.1.0-4002-http_activity-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "http_request": {
                        "properties": {
                            "method": {"type": "keyword"},
                            "url": {
                                "properties": {
                                    "path": {"type": "keyword"},
                                    "full": {"type": "keyword"},
                                    "query": {"type": "keyword"}
                                }
                            },
                            "headers": {"type": "object"},
                            "version": {"type": "keyword"},
                            "bytes": {"type": "long"}
                        }
                    },
                    "http_response": {
                        "properties": {
                            "status_code": {"type": "integer"},
                            "message": {"type": "keyword"},
                            "headers": {"type": "object"},
                            "bytes": {"type": "long"}
                        }
                    },
                    "user_agent": {
                        "properties": {
                            "original": {"type": "keyword"},
                            "device": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "type": {"type": "keyword"}
                                }
                            },
                            "browser": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "version": {"type": "keyword"}
                                }
                            },
                            "os": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "version": {"type": "keyword"}
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
    generator = HTTPActivityGenerator()
    events = [generator.generate_random_event() for _ in range(args.events)]

    # Upload in batches
    current_date = datetime.now().strftime("%Y.%m.%d")
    index_name = f"ocsf-1.1.0-4002-http_activity-{current_date}-000000"
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
