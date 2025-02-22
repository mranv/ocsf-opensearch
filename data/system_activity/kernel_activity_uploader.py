import json
import random
from datetime import datetime, timedelta
from opensearchpy import OpenSearch, helpers
import urllib3
import logging
import argparse
from typing import Dict, Any
import uuid

# Disable SSL warnings
urllib3.disable_warnings()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class KernelActivityGenerator:
    def __init__(self):
        self.kernel_operations = [
            ("module_load", 1),
            ("module_unload", 2),
            ("parameter_change", 3),
            ("syscall", 4),
            ("capability_change", 5)
        ]
        self.kernel_modules = [
            "tcp_cubic",
            "ext4",
            "nvidia",
            "bluetooth",
            "usb_storage",
            "iptable_filter"
        ]
        self.syscalls = [
            "read", "write", "open", "close",
            "fork", "exec", "socket", "connect"
        ]
        self.parameters = [
            "vm.swappiness",
            "net.ipv4.tcp_keepalive_time",
            "kernel.shmmax",
            "net.core.wmem_max"
        ]

    def generate_random_event(self) -> Dict[str, Any]:
        operation, op_id = random.choice(self.kernel_operations)
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 60))
        
        event = {
            "class_uid": 1003,  # Kernel Activity
            "class_name": "Kernel Activity",
            "time": int(timestamp.timestamp() * 1000),
            "activity_id": op_id,
            "activity_name": operation.upper(),
            "status": "Success",
            "status_id": 1,
            "severity": "Info",
            "severity_id": 1,
            "kernel": {
                "version": f"{random.randint(4,6)}.{random.randint(0,19)}.{random.randint(0,99)}",
                "architecture": random.choice(["x86_64", "aarch64", "amd64"]),
                "operation": operation
            },
            "process": {
                "pid": random.randint(1, 65535),
                "name": "kernel_task",
                "path": "/sbin/kernel_task"
            },
            "src_endpoint": {
                "hostname": f"host-{random.randint(1000, 9999)}",
                "uid": str(uuid.uuid4())
            },
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "Kernel Monitor",
                    "vendor_name": "OCSF",
                    "version": "1.0.0"
                },
                "original_time": int(timestamp.timestamp() * 1000)
            }
        }

        # Add operation-specific details
        if operation == "module_load" or operation == "module_unload":
            event["kernel"]["module"] = {
                "name": random.choice(self.kernel_modules),
                "parameters": random.choice(["", "debug=1", "async=true"])
            }
        elif operation == "syscall":
            event["kernel"]["syscall"] = {
                "name": random.choice(self.syscalls),
                "arguments": f"fd={random.randint(0,1000)},size={random.randint(1,4096)}"
            }
        elif operation == "parameter_change":
            param = random.choice(self.parameters)
            event["kernel"]["parameter"] = {
                "name": param,
                "old_value": str(random.randint(100, 1000)),
                "new_value": str(random.randint(100, 1000))
            }

        return event

def main():
    parser = argparse.ArgumentParser(description='Generate kernel activity events')
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
    template_name = "ocsf-1.1.0-1003-kernel_activity"
    template = {
        "index_patterns": ["ocsf-1.1.0-1003-kernel_activity-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "kernel": {
                        "properties": {
                            "version": {"type": "keyword"},
                            "architecture": {"type": "keyword"},
                            "operation": {"type": "keyword"},
                            "module": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "parameters": {"type": "keyword"}
                                }
                            },
                            "syscall": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "arguments": {"type": "keyword"}
                                }
                            },
                            "parameter": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "old_value": {"type": "keyword"},
                                    "new_value": {"type": "keyword"}
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
    generator = KernelActivityGenerator()
    events = [generator.generate_random_event() for _ in range(args.events)]
    
    current_date = datetime.now().strftime("%Y.%m.%d")
    index_name = f"ocsf-1.1.0-1003-kernel_activity-{current_date}-000000"
    
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
