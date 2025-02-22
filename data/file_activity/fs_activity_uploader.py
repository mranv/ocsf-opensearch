import json
import random
from datetime import datetime, timedelta
from opensearchpy import OpenSearch, helpers
import urllib3
import logging
import argparse
from typing import List, Dict, Any

# Disable SSL warnings
urllib3.disable_warnings()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FileSystemActivityGenerator:
    def __init__(self):
        self.users = ["john.doe", "jane.smith", "admin", "root", "jenkins", "mysql", "nginx", "elasticsearch", "tomcat"]
        self.actions = ["create", "modify", "delete", "rename", "chmod", "read", "link"]
        self.paths = [
            "/home/users/documents",
            "/var/www/html",
            "/tmp",
            "/etc",
            "/var/jenkins/workspace",
            "/var/lib/mysql/database",
            "/usr/local/bin",
            "/var/log/nginx",
            "/var/lib/elasticsearch",
            "/backup/daily"
        ]
        self.file_types = [".pdf", ".html", ".json", ".log", ".jar", ".sh", ".docx", ".tar.gz", ".conf", ".txt"]

    def generate_random_event(self) -> Dict[str, Any]:
        """Generate a random file system activity event"""
        user = random.choice(self.users)
        action = random.choice(self.actions)
        base_path = random.choice(self.paths)
        file_type = random.choice(self.file_types)
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 60))
        
        event = {
            "time": int(timestamp.timestamp() * 1000),
            "user": user,
            "pid": random.randint(1000, 9999),
            "action": action,
            "path": f"{base_path}/file_{random.randint(1000, 9999)}{file_type}",
            "size": random.randint(1024, 10485760),  # 1KB to 10MB
            "permissions": random.choice(["644", "600", "755", "640"]),
            "owner": user,
            "group": random.choice(["users", "www-data", "admin", "root"])
        }

        if action == "rename":
            event["new_path"] = f"{base_path}/file_{random.randint(1000, 9999)}{file_type}"
        elif action == "link":
            event["link_path"] = f"/etc/alternatives/file_{random.randint(1000, 9999)}"

        return event

    def map_to_ocsf(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Map file system event to OCSF format"""
        action_map = {
            "create": 1,
            "modify": 2,
            "delete": 3,
            "rename": 4,
            "chmod": 5,
            "read": 6,
            "link": 7
        }

        current_date = datetime.now().strftime("%Y.%m.%d")
        
        ocsf_event = {
            "class_uid": 1001,  # File System Activity
            "class_name": "File System Activity",
            "time": event["time"],
            "activity_id": action_map.get(event["action"], 1),
            "activity_name": event["action"].upper(),
            "status": "Success",
            "status_id": 1,
            "severity": "Informational",
            "severity_id": 1,
            "file": {
                "name": event["path"].split("/")[-1],
                "path": event["path"],
                "size": event["size"],
                "permissions": event["permissions"],
                "owner": {
                    "name": event["owner"],
                    "uid": hash(event["owner"]) % 65535
                },
                "group": {
                    "name": event["group"],
                    "gid": hash(event["group"]) % 65535
                },
                "type": event["path"].split(".")[-1] if "." in event["path"] else "unknown"
            },
            "process": {
                "pid": event["pid"],
                "name": "fs_monitor",
                "path": "/usr/sbin/fs_monitor"
            },
            "actor": {
                "user": {
                    "name": event["user"],
                    "uid": hash(event["user"]) % 65535
                }
            },
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "File System Monitor",
                    "vendor_name": "OCSF",
                    "version": "1.0.0"
                },
                "original_time": event["time"]
            }
        }

        if "new_path" in event:
            ocsf_event["file"]["new_path"] = event["new_path"]
        if "link_path" in event:
            ocsf_event["file"]["link_path"] = event["link_path"]

        return ocsf_event

def main():
    parser = argparse.ArgumentParser(description='Generate and upload file system activity logs to OpenSearch')
    parser.add_argument('--host', default='52.66.102.200', help='OpenSearch host')
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
    template_name = "ocsf-1.1.0-1001-fs_activity"
    template = {
        "index_patterns": ["ocsf-1.1.0-1001-fs_activity-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "file": {
                        "properties": {
                            "owner": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "uid": {"type": "long"}
                                }
                            },
                            "group": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "gid": {"type": "long"}
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

    # Initialize generator
    generator = FileSystemActivityGenerator()

    # Generate and upload events
    events = []
    for _ in range(args.events):
        raw_event = generator.generate_random_event()
        ocsf_event = generator.map_to_ocsf(raw_event)
        events.append(ocsf_event)

    # Upload in batches
    current_date = datetime.now().strftime("%Y.%m.%d")
    index_name = f"ocsf-1.1.0-1001-fs_activity-{current_date}-000000"
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
        except Exception as e:
            logger.error(f"Bulk upload error: {str(e)}")
            failed += len(batch)

    logger.info(f"Upload complete: {successful} successful, {failed} failed")

if __name__ == "__main__":
    main()
