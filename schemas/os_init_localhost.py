#!/usr/bin/env python3

from urllib.parse import urlparse
import zipfile
import os
import json
from opensearchpy import OpenSearch, RequestsHttpConnection
from datetime import datetime

## Initialise variables - Modified for localhost
OSEndpoint = 'https://52.66.102.200:9200'
OS_USERNAME = 'admin'  # Default OpenSearch username, change as needed
OS_PASSWORD = 'Anubhav@321'  # Default OpenSearch password, change as needed

# Local paths to the component and index templates
component_templates_zip = './component_templates.zip'
index_templates_zip = './index_templates.zip'

# Extract paths - where templates will be unzipped
component_templates_dir = './extracted/component_templates'
index_templates_dir = './extracted/index_templates'

print(f"Connecting to OpenSearch at: {OSEndpoint}")

url = urlparse(OSEndpoint)

# Client configuration using basic auth for localhost
client = OpenSearch(
    hosts=[{
        'host': url.netloc.split(':')[0],  # Extract hostname only
        'port': url.port or 9200
    }],
    http_auth=(OS_USERNAME, OS_PASSWORD),
    use_ssl=True,
    verify_certs=False,  # For local development - set to True in production with proper certs
    ssl_show_warn=False,  # Suppress warnings for self-signed certs
    connection_class=RequestsHttpConnection
)

try:
    info = client.info()
    print(f"{info['version']['distribution']}: {info['version']['number']}")
except Exception as e:
    print(f"Failed to connect to OpenSearch: {e}")
    exit(1)

def ISM_INIT():
    ## This function creates the ISM policy
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
        client.plugins.index_management.put_policy(policy = "rollover-expiration-policy", body=ism_policy)
        print("ISM Policy created")
    except Exception as e:
        print(f"Error creating ISM Policy: {e}")
        pass

def alias_init():
    index_date = datetime.now().strftime("%Y.%m.%d")
    index_list = [
        "ocsf-1.1.0-2002-vulnerability_finding", 
        "ocsf-1.1.0-2003-compliance_finding", 
        "ocsf-1.1.0-2004-detection_finding", 
        "ocsf-1.1.0-3001-account_change",
        "ocsf-1.1.0-3002-authentication", 
        "ocsf-1.1.0-4001-network_activity",
        "ocsf-1.1.0-4002-http_activity",
        "ocsf-1.1.0-4003-dns_activity",
        "ocsf-1.1.0-6003-api_activity"
    ]
    
    for index in index_list:
        # Create the index 
        try: 
            index_name = f"<{index}-{{now/d}}-000000>"
            client.indices.create(index=index_name, body={})
            print(f"Created index {index}")
        except Exception as e:
            print(f"Error creating {index} index: {e}")
            pass

        # Create the alias
        try:
            alias_name = index
            alias_index = f"{index}-*"
            client.indices.put_alias(index=alias_index, name=alias_name)
            print(f"Created alias {alias_name}")
        except Exception as e:
            print(f"Error creating {alias_name} alias: {e}")
            pass

        ## Set the index settings
        settings = {
            "settings": {
                "index": {
                    "plugins": {
                        "index_state_management": {
                            "rollover_alias": f"{index}"
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
            pass

def extract_templates(zip_path, extract_to):
    """Extract template zip files to specified directory"""
    # Create extraction directory if it doesn't exist
    os.makedirs(extract_to, exist_ok=True)
    
    try:
        # Unzip the file
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Extract with proper encoding handling
            for file_info in zip_ref.infolist():
                try:
                    # Handle non-ascii filenames safely
                    file_info.filename = file_info.filename.encode('cp437').decode('utf-8', errors='replace')
                except:
                    # If encoding fails, use a safe replacement
                    file_info.filename = file_info.filename.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
                
                # Extract the file, ignoring directory structure if problematic
                try:
                    zip_ref.extract(file_info, extract_to)
                except:
                    # If extraction fails, try with a sanitized filename
                    safe_name = ''.join(c if c.isalnum() or c in '._- ' else '_' for c in file_info.filename)
                    if safe_name:
                        with zip_ref.open(file_info) as source, open(os.path.join(extract_to, safe_name), 'wb') as target:
                            target.write(source.read())
                            
        print(f'File unzipped successfully: {zip_path} to {extract_to}')
        return True
    except FileNotFoundError:
        print(f'Error: The file {zip_path} does not exist')
        return False
    except zipfile.BadZipFile:
        print(f'Error: {zip_path} is not a valid zip file')
        return False
    except Exception as e:
        print(f'Error extracting file: {e}')
        return False

def install_component_templates():
    """Install component templates from local directory"""
    # Extract the component templates zip
    if not extract_templates(component_templates_zip, component_templates_dir):
        print("Skipping component templates installation due to extraction error")
        return False
        
    success_count = 0
    error_count = 0
    
    # Check for missing actor template and create it if needed
    actor_template_exists = False
    
    # Process each template file
    for root, dirs, files in os.walk(component_templates_dir):
        for file in files:
            if file.endswith('_body.json'):
                file_path = os.path.join(root, file)
                template_name = os.path.splitext(file)[0][:-5]  # Remove the "_body" suffix
                
                # Track if we find the actor template
                if template_name == "ocsf_1_1_0_actor":
                    actor_template_exists = True

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        file_content = f.read()
                        try:
                            template_content = json.loads(file_content)
                        except json.JSONDecodeError as e:
                            print(f'Error parsing JSON in {file_path}: {e}')
                            error_count += 1
                            continue

                        try:
                            response = client.cluster.put_component_template(name=template_name, body=template_content)
                            if response.get('acknowledged', False):
                                print(f'Created component template: {template_name}')
                                success_count += 1
                            else:
                                print(f'Error creating component template: {template_name} - {response}')
                                error_count += 1
                        except Exception as e:
                            print(f'Error creating component template: {template_name} - {e}')
                            error_count += 1
                except UnicodeDecodeError as e:
                    print(f'Unicode decode error in {file_path}: {e}')
                    # Try with binary mode and then decode with replacement
                    try:
                        with open(file_path, 'rb') as f:
                            file_content = f.read().decode('utf-8', errors='replace')
                            template_content = json.loads(file_content)
                            response = client.cluster.put_component_template(name=template_name, body=template_content)
                            if response.get('acknowledged', False):
                                print(f'Created component template: {template_name} (after handling encoding issue)')
                                success_count += 1
                            else:
                                print(f'Error creating component template: {template_name} - {response}')
                                error_count += 1
                    except Exception as inner_e:
                        print(f'Failed to handle encoding for {file_path}: {inner_e}')
                        error_count += 1
    
    # Create missing actor template if needed
    if not actor_template_exists:
        try:
            # Create a simple actor template that won't break index templates
            actor_template = {
                "template": {
                    "mappings": {
                        "properties": {
                            "actor": {
                                "type": "object",
                                "properties": {
                                    "user": { "type": "object" },
                                    "process": { "type": "object" },
                                    "session": { "type": "object" }
                                }
                            }
                        }
                    }
                }
            }
            response = client.cluster.put_component_template(name="ocsf_1_1_0_actor", body=actor_template)
            if response.get('acknowledged', False):
                print(f'Created missing actor component template')
                success_count += 1
            else:
                print(f'Error creating actor component template: {response}')
                error_count += 1
        except Exception as e:
            print(f'Error creating actor component template: {e}')
            error_count += 1
            
    # Create missing answers template if needed
    try:
        # Create a simple answers template that won't break DNS index templates
        answers_template = {
            "template": {
                "mappings": {
                    "properties": {
                        "answers": {
                            "type": "nested",
                            "properties": {
                                "data": { "type": "keyword" },
                                "type": { "type": "keyword" }
                            }
                        }
                    }
                }
            }
        }
        response = client.cluster.put_component_template(name="ocsf_1_1_0_answers", body=answers_template)
        if response.get('acknowledged', False):
            print(f'Created missing answers component template')
            success_count += 1
        else:
            print(f'Error creating answers component template: {response}')
            error_count += 1
    except Exception as e:
        print(f'Error creating answers component template: {e}')
        error_count += 1
    
    print(f"Component templates installation completed - Success: {success_count}, Errors: {error_count}")
    return success_count > 0

def install_index_templates():
    """Install index templates from local directory"""
    # Extract the index templates zip
    if not extract_templates(index_templates_zip, index_templates_dir):
        print("Skipping index templates installation due to extraction error")
        return False
        
    success_count = 0
    error_count = 0
    failed_templates = []
    
    # First pass - try to install all templates
    for root, dirs, files in os.walk(index_templates_dir):
        for file in files:
            if file.endswith('_body.json'):
                file_path = os.path.join(root, file)
                template_name = os.path.splitext(file)[0][:-5]  # Remove the "_body" suffix

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        file_content = f.read()
                        try:
                            template_content = json.loads(file_content)
                        except json.JSONDecodeError as e:
                            print(f'Error parsing JSON in {file_path}: {e}')
                            error_count += 1
                            # Store for retry with binary read
                            failed_templates.append((template_name, file_path, "json_error"))
                            continue

                        try:
                            response = client.indices.put_index_template(name=template_name, body=template_content)
                            if response.get('acknowledged', False):
                                print(f'Created index template: {template_name}')
                                success_count += 1
                            else:
                                print(f'Error creating index template: {template_name} - {response}')
                                error_count += 1
                                # Track failed templates for potential retry
                                failed_templates.append((template_name, file_path, "api_error"))
                        except Exception as e:
                            print(f'Error creating index template: {template_name} - {e}')
                            error_count += 1
                            # Track failed templates for potential retry
                            failed_templates.append((template_name, file_path, "exception", str(e)))
                except UnicodeDecodeError as e:
                    print(f'Unicode decode error in {file_path}: {e}')
                    # Track for retry with binary mode
                    failed_templates.append((template_name, file_path, "encoding_error"))
                    error_count += 1

    # Second pass - try to fix problematic templates
    for template_info in failed_templates:
        template_name, file_path, error_type, *extra = template_info
        
        if error_type == "encoding_error":
            # Try with binary read and replacement of bad chars
            try:
                with open(file_path, 'rb') as f:
                    content_bytes = f.read()
                    # Try to decode with replacement
                    file_content = content_bytes.decode('utf-8', errors='replace')
                    template_content = json.loads(file_content)
                    
                    try:
                        response = client.indices.put_index_template(name=template_name, body=template_content)
                        if response.get('acknowledged', False):
                            print(f'Created index template: {template_name} (after handling encoding issue)')
                            success_count += 1
                            error_count -= 1
                    except Exception as e:
                        print(f'Still failed to create index template after fixing encoding: {template_name} - {e}')
                        # Already counted as error, no need to increment
            except Exception as e:
                print(f'Could not recover from encoding error for {template_name}: {e}')
        
        elif error_type == "json_error":
            # Try with UTF-8 + BOM or other encodings
            for encoding in ['utf-8-sig', 'latin1', 'cp1252']:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        file_content = f.read()
                        template_content = json.loads(file_content)
                        
                        response = client.indices.put_index_template(name=template_name, body=template_content)
                        if response.get('acknowledged', False):
                            print(f'Created index template: {template_name} (using {encoding} encoding)')
                            success_count += 1
                            error_count -= 1
                            break  # Success, no need to try other encodings
                except:
                    continue  # Try next encoding
    
    print(f"Index templates installation completed - Success: {success_count}, Errors: {error_count}")
    return success_count > 0

def main():
    """Main function to initialize OpenSearch"""
    print("=== Starting OpenSearch initialization ===")
    
    # Install templates
    component_result = install_component_templates()
    index_result = install_index_templates()
    
    # Initialize ISM policy and aliases if templates were installed
    if component_result or index_result:
        try:
            ISM_INIT()
        except Exception as e:
            print(f"Error initializing ISM policy: {e}")
        
        try:
            alias_init()
        except Exception as e:
            print(f"Error initializing aliases: {e}")
    
    print("=== OpenSearch initialization complete ===")

if __name__ == "__main__":
    main()