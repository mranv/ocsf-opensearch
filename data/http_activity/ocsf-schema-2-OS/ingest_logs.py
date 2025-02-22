import requests
import json
import time
import logging
from datetime import datetime
import urllib3
from typing import Dict, Any
import os

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class OCSFHttpActivityIngestor:
    def __init__(
        self,
        opensearch_host: str = "https://52.66.102.200:9200",
        username: str = "admin",
        password: str = "Anubhav@321",
        index_name: str = "ocsf-http-activity",
        refresh_interval: int = 5  # seconds
    ):
        self.opensearch_host = opensearch_host
        self.auth = (username, password)
        self.index_name = index_name
        self.refresh_interval = refresh_interval
        self.api_url = "https://schema.ocsf.io/sample/1.1.0/classes/http_activity?profiles="
        self.verify_ssl = False

    def create_index_template(self) -> bool:
        """Create or update index template"""
        template = {
            "index_patterns": [f"{self.index_name}*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1
                },
                "mappings": {
                    "properties": {
                        "time": {"type": "date"},
                        "http_request": {
                            "properties": {
                                "method": {"type": "keyword"},
                                "url": {
                                    "properties": {
                                        "path": {"type": "keyword"},
                                        "port": {"type": "integer"},
                                        "scheme": {"type": "keyword"}
                                    }
                                }
                            }
                        },
                        "http_response": {
                            "properties": {
                                "code": {"type": "integer"},
                                "latency": {"type": "long"}
                            }
                        },
                        "metadata": {
                            "properties": {
                                "version": {"type": "keyword"},
                                "product": {
                                    "properties": {
                                        "name": {"type": "keyword"},
                                        "vendor_name": {"type": "keyword"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        try:
            url = f"{self.opensearch_host}/_index_template/{self.index_name}-template"
            response = requests.put(
                url,
                json=template,
                auth=self.auth,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            logger.info("Index template created/updated successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to create index template: {e}")
            return False

    def fetch_sample_data(self) -> Dict[str, Any]:
        """Fetch new sample data from OCSF API"""
        try:
            response = requests.get(self.api_url)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to fetch data: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error fetching data: {e}")
            return None

    def ingest_data(self, data: Dict[str, Any]) -> bool:
        """Ingest data into OpenSearch"""
        try:
            # Add timestamp if not present
            if 'time' not in data:
                data['time'] = int(datetime.now().timestamp() * 1000)

            url = f"{self.opensearch_host}/{self.index_name}/_doc"
            response = requests.post(
                url,
                json=data,
                auth=self.auth,
                verify=self.verify_ssl,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            logger.info(f"Successfully ingested document: {response.json().get('_id')}")
            return True
        except Exception as e:
            logger.error(f"Failed to ingest data: {e}")
            return False

    def run_continuous_ingestion(self):
        """Run continuous ingestion loop"""
        logger.info("Starting continuous ingestion...")
        
        # Create/update index template
        if not self.create_index_template():
            logger.error("Failed to create index template. Exiting.")
            return

        while True:
            try:
                # Fetch new data
                data = self.fetch_sample_data()
                if data:
                    # Ingest data
                    if self.ingest_data(data):
                        logger.info(f"Waiting {self.refresh_interval} seconds before next fetch...")
                    else:
                        logger.warning("Failed to ingest data, will retry...")
                
                # Wait before next fetch
                time.sleep(self.refresh_interval)
                
            except KeyboardInterrupt:
                logger.info("Received interrupt, stopping ingestion...")
                break
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                time.sleep(self.refresh_interval)

def main():
    # Initialize ingestor with custom settings
    ingestor = OCSFHttpActivityIngestor(
        opensearch_host="https://52.66.102.200:9200",
        username="admin",
        password="Anubhav@321",
        refresh_interval=5  # Fetch new data every 5 seconds
    )
    
    # Start continuous ingestion
    ingestor.run_continuous_ingestion()

if __name__ == "__main__":
    main()