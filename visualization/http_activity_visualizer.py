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
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HTTPActivityVisualizer:
    def __init__(self):
        self.http_methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]
        self.paths = [
            "/api/v1/users",
            "/api/v1/products",
            "/api/v1/orders",
            "/login",
            "/logout",
            "/dashboard",
            "/reports",
            "/settings"
        ]
        self.status_codes = [
            (200, 60),  # (code, weight)
            (201, 10),
            (301, 5),
            (400, 10),
            (401, 5),
            (403, 5),
            (404, 3),
            (500, 2)
        ]
        self.user_agents = [
            ("Chrome", 40),
            ("Firefox", 30),
            ("Safari", 20),
            ("Mobile", 10)
        ]

    def generate_timed_events(self, count: int, start_time: datetime, end_time: datetime) -> list:
        """Generate events distributed over a time period"""
        events = []
        time_range = (end_time - start_time).total_seconds()
        
        for _ in range(count):
            # Generate timestamp within the range
            seconds = random.uniform(0, time_range)
            timestamp = start_time + timedelta(seconds=seconds)
            
            # Create event
            event = self.generate_event(timestamp)
            events.append(event)
        
        # Sort events by timestamp
        return sorted(events, key=lambda x: x['time'])

    def generate_event(self, timestamp: datetime) -> Dict[str, Any]:
        """Generate a single HTTP activity event"""
        method = random.choice(self.http_methods)
        path = random.choice(self.paths)
        status_code = random.choices(
            [x[0] for x in self.status_codes],
            weights=[x[1] for x in self.status_codes]
        )[0]
        user_agent_type = random.choices(
            [x[0] for x in self.user_agents],
            weights=[x[1] for x in self.user_agents]
        )[0]

        event = {
            "class_uid": 4002,
            "class_name": "HTTP Activity",
            "time": int(timestamp.timestamp() * 1000),
            "activity_id": 1,
            "activity_name": "HTTP_REQUEST",
            "status": "Success" if status_code < 400 else "Failure",
            "status_id": 1 if status_code < 400 else 2,
            "severity_id": 1 if status_code < 400 else (2 if status_code < 500 else 3),
            "severity": "Info" if status_code < 400 else ("Medium" if status_code < 500 else "High"),
            "http_request": {
                "method": method,
                "url": {
                    "path": path,
                    "full": f"https://example.com{path}"
                },
                "bytes": random.randint(100, 10000)
            },
            "http_response": {
                "status_code": status_code,
                "bytes": random.randint(100, 50000)
            },
            "src_endpoint": {
                "ip": str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1))),
                "geo": {
                    "country": "United States",
                    "city": "New York"
                }
            },
            "user_agent": {
                "type": user_agent_type,
                "original": f"Mozilla/5.0 ({user_agent_type})"
            }
        }
        
        return event

def main():
    parser = argparse.ArgumentParser(description='Generate HTTP activity visualization data')
    parser.add_argument('--host', default='52.66.102.200', help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--user', default='admin', help='OpenSearch username')
    parser.add_argument('--password', default='Anubhav@321', help='OpenSearch password')
    parser.add_argument('--events', type=int, default=1000, help='Number of events to generate')
    parser.add_argument('--hours', type=int, default=24, help='Hours of data to generate')

    args = parser.parse_args()

    # Calculate time range
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=args.hours)

    # Initialize visualizer and generate events
    visualizer = HTTPActivityVisualizer()
    events = visualizer.generate_timed_events(args.events, start_time, end_time)

    # Initialize OpenSearch client
    client = OpenSearch(
        hosts=[{'host': args.host, 'port': args.port}],
        http_auth=(args.user, args.password),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False
    )

    # Create index with visualization-friendly mappings
    index_name = f"ocsf-1.1.0-4002-http_activity-{end_time.strftime('%Y.%m.%d')}-000000"
    mapping = {
        "mappings": {
            "properties": {
                "time": {"type": "date"},
                "http_request": {
                    "properties": {
                        "method": {"type": "keyword"},
                        "url": {
                            "properties": {
                                "path": {"type": "keyword"}
                            }
                        }
                    }
                },
                "http_response": {
                    "properties": {
                        "status_code": {"type": "integer"}
                    }
                },
                "user_agent": {
                    "properties": {
                        "type": {"type": "keyword"}
                    }
                },
                "src_endpoint": {
                    "properties": {
                        "geo": {
                            "properties": {
                                "country": {"type": "keyword"},
                                "city": {"type": "keyword"}
                            }
                        }
                    }
                }
            }
        }
    }

    try:
        client.indices.create(index=index_name, body=mapping)
    except Exception as e:
        logger.warning(f"Index already exists or error: {e}")

    # Upload events in batches
    batch_size = 100
    successful = 0
    failed = 0

    for i in range(0, len(events), batch_size):
        batch = events[i:i + batch_size]
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
        except Exception as e:
            logger.error(f"Bulk upload error: {str(e)}")
            failed += len(batch)

    logger.info(f"Upload complete: {successful} successful, {failed} failed")
    logger.info(f"Data available in index: {index_name}")
    logger.info("""
To visualize the data:
1. Open OpenSearch Dashboards
2. Go to Visualize
3. Create visualizations for:
   - HTTP Methods distribution (Pie Chart)
   - Status Codes over time (Line Chart)
   - Top Paths (Bar Chart)
   - Geographic distribution (Map)
   - User Agent distribution (Pie Chart)
4. Create a dashboard combining these visualizations
""")

if __name__ == "__main__":
    main()
