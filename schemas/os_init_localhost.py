import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from urllib.parse import urlparse
import os
import json
from opensearchpy import OpenSearch, RequestsHttpConnection
from datetime import datetime

# Connection details for your OpenSearch instance on https://52.66.102.200:9200
OSEndpoint = 'https://52.66.102.200:9200'
OS_USERNAME = 'admin'
OS_PASSWORD = 'Anubhav@321'

print("OpenSearch Endpoint:", OSEndpoint)
region = os.environ.get('AWS_REGION', 'local')
print("Region:", region)

url = urlparse(OSEndpoint)

# Configure the OpenSearch client.
client = OpenSearch(
    hosts=[{'host': url.hostname, 'port': url.port or 9200}],
    http_auth=(OS_USERNAME, OS_PASSWORD),
    use_ssl=True,
    verify_certs=False,  # Using self-signed certificates; disable verification
    connection_class=RequestsHttpConnection
)

# Print cluster information
info = client.info()
print(f"{info['version']['distribution']}: {info['version']['number']}")

def ISM_INIT():
    """
    Create the Index State Management (ISM) policy.
    """
    ism_policy = {
        "policy": {
            "policy_id": "rollover-expiration-policy",
            "description": "This policy rollsover the index daily or if it reaches 40gb. It also expires logs older than 15 days",
            "default_state": "rollover",
            "states": [
                {
                    "name": "rollover",
                    "actions": [
                        {
                            "retry": {
                                "count": 3,
                                "backoff": "exponential",
                                "delay": "1h"
                            },
                            "rollover": {
                                "min_size": "40gb",
                                "min_index_age": "1d",
                                "copy_alias": False
                            }
                        }
                    ],
                    "transitions": [
                        {
                            "state_name": "hot"
                        }
                    ]
                },
                {
                    "name": "hot",
                    "actions": [],
                    "transitions": [
                        {
                            "state_name": "delete",
                            "conditions": {
                                "min_index_age": "15d"
                            }
                        }
                    ]
                },
                {
                    "name": "delete",
                    "actions": [
                        {
                            "timeout": "5h",
                            "retry": {
                                "count": 3,
                                "backoff": "exponential",
                                "delay": "1h"
                            },
                            "delete": {}
                        }
                    ],
                    "transitions": []
                }
            ],
            "ism_template": [
                {
                    "index_patterns": [
                        "ocsf-*"
                    ],
                    "priority": 9
                }
            ]
        }
    }
    try:
        client.plugins.index_management.put_policy(policy="rollover-expiration-policy", body=ism_policy)
        print("ISM Policy created")
    except Exception as e:
        print(f"Error creating ISM Policy: {e}")

def alias_init():
    """
    Create indices and assign aliases with rollover settings.
    """
    index_list = [
        "ocsf-1.1.0-2002-vulnerability_finding",
        "ocsf-1.1.0-2003-compliance_finding",
        "ocsf-1.1.0-2004-detection_finding",
        "ocsf-1.1.0-3001-account_change",
        "ocsf-1.1.0-3002-authentication",
        "ocsf-1.1.0-4001-network_activity",
        "ocsf-1.1.0-4002-http_activity",
        "ocsf-1.1.0-4003-dns_activity",
        "ocsf-1.1.0-6003-api_activity",
    ]
    for index in index_list:
        # Create the index using the rollover alias notation
        try:
            index_name = f"<{index}-{{now/d}}-000000>"
            client.indices.create(index=index_name, body={})
            print(f"Created index {index}")
        except Exception as e:
            print(f"Error creating {index} index: {e}")

        # Create the alias for the index
        try:
            alias_name = index
            alias_index = f"{index}-*"
            client.indices.put_alias(index=alias_index, name=alias_name)
            print(f"Created alias {alias_name}")
        except Exception as e:
            print(f"Error creating alias {alias_name}: {e}")

        # Set the index settings for rollover alias
        settings = {
            "settings": {
                "index": {
                    "plugins": {
                        "index_state_management": {
                            "rollover_alias": alias_name
                        }
                    }
                }
            }
        }
        try:
            client.indices.put_settings(index=index_name, body=settings)
            print(f"Applied settings to {index_name}")
        except Exception as e:
            print(f"Error applying settings to {index_name}: {e}")

def install_component_templates():
    """
    Install component templates from the local 'component_templates' directory.
    """
    local_dir = os.path.join(os.getcwd(), 'component_templates')
    if not os.path.exists(local_dir):
        print(f"Component templates directory {local_dir} does not exist.")
        return

    for root, dirs, files in os.walk(local_dir):
        for file in files:
            if file.endswith('_body.json'):
                file_path = os.path.join(root, file)
                # Remove the '_body' suffix from the file name
                template_name = os.path.splitext(file)[0]
                if template_name.endswith('_body'):
                    template_name = template_name[:-5]

                with open(file_path, 'r') as f:
                    template_content = json.load(f)

                try:
                    response = client.cluster.put_component_template(name=template_name, body=template_content)
                    if response.get('acknowledged'):
                        print(f"Created component template: {template_name}")
                    else:
                        print(f"Error creating component template: {template_name} - {response}")
                except Exception as e:
                    print(f"Error creating component template: {template_name} - {e}")

def install_index_templates():
    """
    Install index templates from the local 'index_templates' directory.
    """
    local_dir = os.path.join(os.getcwd(), 'index_templates')
    if not os.path.exists(local_dir):
        print(f"Index templates directory {local_dir} does not exist.")
        return

    for root, dirs, files in os.walk(local_dir):
        for file in files:
            if file.endswith('_body.json'):
                file_path = os.path.join(root, file)
                # Remove the '_body' suffix from the file name
                template_name = os.path.splitext(file)[0]
                if template_name.endswith('_body'):
                    template_name = template_name[:-5]

                with open(file_path, 'r') as f:
                    template_content = json.load(f)

                try:
                    response = client.indices.put_index_template(name=template_name, body=template_content)
                    if response.get('acknowledged'):
                        print(f"Created index template: {template_name}")
                    else:
                        print(f"Error creating index template: {template_name} - {response}")
                except Exception as e:
                    print(f"Error creating index template: {template_name} - {e}")

def main():
    install_component_templates()
    install_index_templates()
    ISM_INIT()
    alias_init()

if __name__ == '__main__':
    main()
