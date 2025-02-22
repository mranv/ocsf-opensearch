import sys
import json
import random
from datetime import datetime, timedelta
from opensearchpy import OpenSearch, helpers
import urllib3
import logging
import argparse
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import importlib.util
import os

# Disable SSL warnings
urllib3.disable_warnings()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('ocsf_composer.log')
    ]
)
logger = logging.getLogger(__name__)

class OCSFComposer:
    def __init__(self, opensearch_config: Dict[str, Any]):
        self.opensearch_config = opensearch_config
        self.generators = {}
        self.client = self._init_opensearch()

    def _init_opensearch(self) -> OpenSearch:
        """Initialize OpenSearch client"""
        return OpenSearch(
            hosts=[{
                'host': self.opensearch_config['host'],
                'port': self.opensearch_config['port']
            }],
            http_auth=(self.opensearch_config['user'], self.opensearch_config['password']),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False
        )

    def import_generator(self, generator_path: str, class_name: str, module_name: str = None):
        """Dynamically import a generator class"""
        try:
            if module_name is None:
                module_name = f"ocsf_{class_name.lower()}"

            spec = importlib.util.spec_from_file_location(module_name, generator_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            generator_class = getattr(module, class_name)
            self.generators[class_name] = generator_class()
            logger.info(f"Successfully imported generator: {class_name}")
        except Exception as e:
            logger.error(f"Failed to import generator {class_name}: {str(e)}")

    def generate_batch(self, generator_name: str, count: int) -> List[Dict[str, Any]]:
        """Generate a batch of events using specified generator"""
        if generator_name not in self.generators:
            raise ValueError(f"Generator not found: {generator_name}")
        
        return [self.generators[generator_name].generate_random_event() 
                for _ in range(count)]

    def upload_events(self, events: List[Dict[str, Any]], index_name: str, batch_size: int = 100) -> tuple:
        """Upload events to OpenSearch"""
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
                success, failed_items = helpers.bulk(
                    self.client, actions, stats_only=False, raise_on_error=False
                )
                successful += success
                if failed_items:
                    failed += len(failed_items)
                    logger.error(f"Failed items: {failed_items}")
            except Exception as e:
                logger.error(f"Bulk upload error: {str(e)}")
                failed += len(batch)

        return successful, failed

def main():
    parser = argparse.ArgumentParser(description='OCSF Event Generator Composer')
    parser.add_argument('--host', default='52.66.102.200', help='OpenSearch host')
    parser.add_argument('--port', type=int, default=9200, help='OpenSearch port')
    parser.add_argument('--user', default='admin', help='OpenSearch username')
    parser.add_argument('--password', default='Anubhav@321', help='OpenSearch password')
    parser.add_argument('--batch-size', type=int, default=100, help='Upload batch size')
    parser.add_argument('--events-per-type', type=int, default=10, help='Number of events per type')
    
    args = parser.parse_args()

    # Initialize composer
    composer = OCSFComposer({
        'host': args.host,
        'port': args.port,
        'user': args.user,
        'password': args.password
    })

    # Import all generators
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    generators_config = [
        {
            'path': f"{base_path}/http_activity/http_activity_uploader.py",
            'class': 'HTTPActivityGenerator',
            'index': 'ocsf-1.1.0-4002-http_activity'
        },
        {
            'path': f"{base_path}/dns_activity/dns_activity_uploader.py",
            'class': 'DNSActivityGenerator',
            'index': 'ocsf-1.1.0-4003-dns_activity'
        },
        {
            'path': f"{base_path}/authentication/auth_activity_uploader.py",
            'class': 'AuthenticationGenerator',
            'index': 'ocsf-1.1.0-3002-authentication'
        },
        {
            'path': f"{base_path}/account_activity/account_change_uploader.py",
            'class': 'AccountChangeGenerator',
            'index': 'ocsf-1.1.0-3001-account_change'
        },
        {
            'path': f"{base_path}/file_activity/fs_activity_uploader.py",
            'class': 'FileSystemActivityGenerator',
            'index': 'ocsf-1.1.0-1001-fs_activity'
        }
    ]

    # Import all generators
    for config in generators_config:
        composer.import_generator(config['path'], config['class'])

    current_date = datetime.now().strftime("%Y.%m.%d")
    total_successful = 0
    total_failed = 0

    # Generate and upload events for each type
    for config in generators_config:
        try:
            logger.info(f"Generating {args.events_per_type} events for {config['class']}")
            events = composer.generate_batch(config['class'], args.events_per_type)
            
            index_name = f"{config['index']}-{current_date}-000000"
            logger.info(f"Uploading to index: {index_name}")
            
            successful, failed = composer.upload_events(
                events, index_name, args.batch_size
            )
            
            total_successful += successful
            total_failed += failed
            
            logger.info(f"Completed {config['class']}: {successful} successful, {failed} failed")
            
        except Exception as e:
            logger.error(f"Error processing {config['class']}: {str(e)}")

    # Print final summary
    logger.info("=" * 50)
    logger.info("Final Summary:")
    logger.info(f"Total events processed: {args.events_per_type * len(generators_config)}")
    logger.info(f"Total successful: {total_successful}")
    logger.info(f"Total failed: {total_failed}")
    logger.info(f"Overall success rate: {(total_successful/(total_successful + total_failed))*100:.2f}%")
    logger.info("=" * 50)

if __name__ == "__main__":
    main()
