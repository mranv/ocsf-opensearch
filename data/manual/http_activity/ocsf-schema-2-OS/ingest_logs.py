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
        index_name: str = "ocsf-1.1.0-4002-http_activity",  # Changed default index name
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
            "index_patterns": ["ocsf-1.1.0-4002*"],
            "template": {
                "settings": {
                    "index.plugins.index_state_management.rollover_alias": "ocsf-1.1.0-4002-http_activity",
                    "number_of_shards": 1,
                    "number_of_replicas": 1,
                    "index.max_docvalue_fields_search": 400,
                    "index.mapping.total_fields.limit": 4000
                },
                "mappings": {
                    "properties": {
                        "action": {
                            "type": "keyword",
                            "ignore_above": 64
                        },
                        "action_id": {
                            "type": "integer"
                        },
                        "app_name": {
                            "type": "keyword",
                            "ignore_above": 64
                        },
                        "disposition": {
                            "type": "keyword",
                            "ignore_above": 64
                        },
                        "disposition_id": {
                            "type": "integer"
                        }
                    }
                }
            },
            "composed_of": [
                "ocsf_1_1_0_api",
                "ocsf_1_1_0_actor",
                "ocsf_1_1_0_attacks",
                "ocsf_1_1_0_authorizations",
                "ocsf_1_1_0_base_event",
                "ocsf_1_1_0_cloud",
                "ocsf_1_1_0_connection_info",
                "ocsf_1_1_0_dst_endpoint",
                "ocsf_1_1_0_device",
                "ocsf_1_1_0_enrichments",
                "ocsf_1_1_0_firewall_rule",
                "ocsf_1_1_0_http_cookies",
                "ocsf_1_1_0_http_request",
                "ocsf_1_1_0_http_response",
                "ocsf_1_1_0_load_balancer",
                "ocsf_1_1_0_malware",
                "ocsf_1_1_0_metadata",
                "ocsf_1_1_0_observables",
                "ocsf_1_1_0_proxy_endpoint",
                "ocsf_1_1_0_proxy_connection_information",
                "ocsf_1_1_0_proxy_http_request",
                "ocsf_1_1_0_proxy_http_response",
                "ocsf_1_1_0_proxy_tls",
                "ocsf_1_1_0_proxy_traffic",
                "ocsf_1_1_0_src_endpoint",
                "ocsf_1_1_0_tls",
                "ocsf_1_1_0_traffic"
            ],
            "version": 1,
            "_meta": {
                "description": "4002 HTTP Activity - schema version OCSF v1.1.0"
            }
        }

        try:
            # Change the template name to match the pattern
            template_name = "ocsf_1_1_0_4002_http_activity"
            url = f"{self.opensearch_host}/_index_template/{template_name}"
            response = requests.put(
                url,
                json=template,
                auth=self.auth,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            logger.info(f"Index template created/updated successfully: {template_name}")
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