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

class DatabaseActivityGenerator:
    def __init__(self):
        self.db_operations = [
            ("SELECT", 1),
            ("INSERT", 2),
            ("UPDATE", 3),
            ("DELETE", 4),
            ("CREATE", 5),
            ("ALTER", 6),
            ("DROP", 7),
            ("GRANT", 8),
            ("REVOKE", 9)
        ]
        
        self.databases = [
            ("users_db", "Users Database"),
            ("orders_db", "Orders Management"),
            ("products_db", "Product Catalog"),
            ("analytics_db", "Analytics Data"),
            ("audit_db", "Audit Logs")
        ]
        
        self.tables = {
            "users_db": ["users", "roles", "permissions", "sessions"],
            "orders_db": ["orders", "order_items", "shipments", "invoices"],
            "products_db": ["products", "categories", "inventory", "suppliers"],
            "analytics_db": ["events", "metrics", "reports", "dashboards"],
            "audit_db": ["access_logs", "changes", "alerts", "incidents"]
        }
        
        self.users = [
            "db_admin",
            "app_user",
            "reporting_user",
            "backup_user",
            "readonly_user"
        ]

    def generate_random_event(self) -> Dict[str, Any]:
        operation, op_id = random.choice(self.db_operations)
        db_name, db_desc = random.choice(self.databases)
        timestamp = datetime.now() - timedelta(minutes=random.randint(0, 60))
        table = random.choice(self.tables[db_name])
        user = random.choice(self.users)
        
        event = {
            "class_uid": 5001,  # Database Activity
            "class_name": "Database Activity",
            "time": int(timestamp.timestamp() * 1000),
            "activity_id": op_id,
            "activity_name": operation,
            "status": "Success",
            "status_id": 1,
            "severity": "Info",
            "severity_id": 1,
            "database": {
                "name": db_name,
                "instance": f"{db_name}-{random.randint(1,5)}",
                "schema": table,
                "operation": operation,
                "query": self.generate_query(operation, table)
            },
            "actor": {
                "user": {
                    "name": user,
                    "uid": str(uuid.uuid4()),
                    "type": "Database User"
                }
            },
            "src_endpoint": {
                "ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
                "hostname": f"app-server-{random.randint(1,100)}"
            },
            "dst_endpoint": {
                "ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
                "hostname": f"db-server-{random.randint(1,10)}",
                "port": 3306
            },
            "metadata": {
                "version": "1.1.0",
                "product": {
                    "name": "Database Monitor",
                    "vendor_name": "OCSF",
                    "version": "1.0.0"
                },
                "original_time": int(timestamp.timestamp() * 1000)
            }
        }

        # Add operation-specific details
        if operation in ["INSERT", "UPDATE", "DELETE"]:
            event["database"]["rows_affected"] = random.randint(1, 1000)
        
        if operation in ["SELECT"]:
            event["database"]["rows_returned"] = random.randint(1, 10000)
            
        if operation in ["GRANT", "REVOKE"]:
            event["database"]["privileges"] = random.sample(
                ["SELECT", "INSERT", "UPDATE", "DELETE", "ALL"], 
                k=random.randint(1, 3)
            )

        return event

    def generate_query(self, operation: str, table: str) -> str:
        """Generate a sample SQL query based on the operation"""
        if operation == "SELECT":
            return f"SELECT * FROM {table} WHERE id = ?"
        elif operation == "INSERT":
            return f"INSERT INTO {table} (column1, column2) VALUES (?, ?)"
        elif operation == "UPDATE":
            return f"UPDATE {table} SET column1 = ? WHERE id = ?"
        elif operation == "DELETE":
            return f"DELETE FROM {table} WHERE id = ?"
        elif operation == "CREATE":
            return f"CREATE TABLE {table} (id INT PRIMARY KEY, name VARCHAR(255))"
        elif operation == "ALTER":
            return f"ALTER TABLE {table} ADD COLUMN new_column VARCHAR(255)"
        elif operation == "DROP":
            return f"DROP TABLE {table}"
        elif operation == "GRANT":
            return f"GRANT SELECT, INSERT ON {table} TO user"
        elif operation == "REVOKE":
            return f"REVOKE ALL ON {table} FROM user"
        return ""

def main():
    parser = argparse.ArgumentParser(description='Generate and upload database activity events to OpenSearch')
    parser.add_argument('--host', default='52.66.102.200', help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--user', default='admin', help='OpenSearch username')
    parser.add_argument('--password', default='Anubhav@321', help='OpenSearch password')
    parser.add_argument('--events', type=int, default=10, help='Number of events to generate')
    parser.add_argument('--batch-size', type=int, default=5, help='Upload batch size')

    args = parser.parse_args()
    logger.info("Starting database activity event generation and upload")

    try:
        # Initialize OpenSearch client
        client = OpenSearch(
            hosts=[{'host': args.host, 'port': args.port}],
            http_auth=(args.user, args.password),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False
        )

        # Verify connection
        cluster_info = client.info()
        logger.info(f"Connected to OpenSearch cluster: {cluster_info.get('cluster_name', 'unknown')}")

        # Create index template
        template_name = "ocsf-1.1.0-5001-database_activity"
        template = {
            "index_patterns": ["ocsf-1.1.0-5001-database_activity-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1
                },
                "mappings": {
                    "properties": {
                        "database": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "instance": {"type": "keyword"},
                                "schema": {"type": "keyword"},
                                "operation": {"type": "keyword"},
                                "query": {"type": "keyword"},
                                "rows_affected": {"type": "long"},
                                "rows_returned": {"type": "long"},
                                "privileges": {"type": "keyword"}
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
                                "hostname": {"type": "keyword"}
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

        client.indices.put_template(name=template_name, body=template)
        logger.info(f"Created index template: {template_name}")

        # Initialize generator and generate events
        generator = DatabaseActivityGenerator()
        events = [generator.generate_random_event() for _ in range(args.events)]
        
        # Upload in batches
        current_date = datetime.now().strftime("%Y.%m.%d")
        index_name = f"ocsf-1.1.0-5001-database_activity-{current_date}-000000"
        successful = 0
        failed = 0

        for i in range(0, len(events), args.batch_size):
            batch = events[i:i + args.batch_size]
            batch_num = (i // args.batch_size) + 1
            logger.info(f"Processing batch {batch_num}/{(len(events) + args.batch_size - 1) // args.batch_size}")
            
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

    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Process interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error("Unexpected error: {str(e)}")
        sys.exit(1)
