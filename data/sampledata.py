#!/usr/bin/env python3

import json
import os
from opensearchpy import OpenSearch, RequestsHttpConnection
from datetime import datetime
import hashlib
import uuid

# OpenSearch connection configuration
OS_HOST = "localhost"
OS_PORT = 9200
OS_USERNAME = "admin"  # Default OpenSearch username, change as needed
OS_PASSWORD = "Anubhav@321"  # Default OpenSearch password, change as needed
USE_SSL = True
VERIFY_CERTS = False  # For local development - set to True in production with proper certs

# Sample data file location
SAMPLE_DATA_FILE = "sample_data.json"

def create_opensearch_client():
    """Create and return an OpenSearch client"""
    client = OpenSearch(
        hosts=[{'host': OS_HOST, 'port': OS_PORT}],
        http_auth=(OS_USERNAME, OS_PASSWORD),
        use_ssl=USE_SSL,
        verify_certs=VERIFY_CERTS,
        ssl_show_warn=False,  # Suppress warnings for self-signed certs
        connection_class=RequestsHttpConnection
    )
    
    # Test connection
    try:
        info = client.info()
        print(f"Connected to {info['version']['distribution']} {info['version']['number']}")
        return client
    except Exception as e:
        print(f"Failed to connect to OpenSearch: {e}")
        exit(1)

def determine_index(document):
    """Determine the appropriate index based on document content"""
    # Default index
    index = "ocsf-1.1.0-4002-http_activity"
    
    # Check for event category/type to determine index
    if "event" in document:
        event = document.get("event", {})
        category = event.get("category", "")
        type_value = event.get("type", "")
        result = event.get("result", "")
        
        # Web/HTTP events
        if category == "web" and type_value == "access":
            index = "ocsf-1.1.0-4002-http_activity"
        # Authentication events
        elif category == "authentication":
            index = "ocsf-1.1.0-3002-authentication"
        # Network events
        elif category in ["network", "connection"]:
            index = "ocsf-1.1.0-4001-network_activity"
        # Error/Security events
        elif type_value == "error" or category == "error":
            if "security" in str(document).lower():
                index = "ocsf-1.1.0-2004-detection_finding"
            else:
                index = "ocsf-1.1.0-4002-http_activity"  # Default to HTTP for web errors
        # API activity
        elif category == "api" or "api" in str(document).lower():
            index = "ocsf-1.1.0-6003-api_activity"
            
    # DNS-specific detection
    if "dns" in str(document).lower():
        index = "ocsf-1.1.0-4003-dns_activity"
        
    return index

def transform_to_ocsf(document):
    """Transform generic logs to OCSF format if needed"""
    # Fix known schema issues
    
    # 1. Fix timestamp format if needed
    if "observedTimestamp" in document and ":" in document["observedTimestamp"] and "T" not in document["observedTimestamp"]:
        parts = document["observedTimestamp"].split(":")
        if len(parts) >= 3:
            # Replace the first : with T to make it ISO format
            document["observedTimestamp"] = document["observedTimestamp"].replace(":", "T", 1)
    
    # 2. Fix severity structure if it's an object
    if "severity" in document and isinstance(document["severity"], dict) and "text" in document["severity"]:
        document["severity"] = document["severity"]["text"]
    
    # Skip further transformation if already in OCSF-compatible format
    if "@timestamp" in document:
        return document
    
    # Create a basic OCSF structure
    ocsf_doc = {
        "@timestamp": datetime.now().isoformat(),
        "observedTimestamp": datetime.now().isoformat(),
        "metadata": {
            "product": {
                "name": "Custom Logger",
                "vendor_name": "LocalSystem"
            },
            "version": "1.0.0",
            "profiles": ["ocsf"]
        }
    }
    
    # Merge the original document
    ocsf_doc.update(document)
    
    # Ensure required fields
    if "event" not in ocsf_doc:
        ocsf_doc["event"] = {"category": "logs", "type": "raw"}
    
    # Generate trace ID if not present
    if "traceId" not in ocsf_doc:
        ocsf_doc["traceId"] = str(uuid.uuid4())
    
    return ocsf_doc

def load_and_send_data(client):
    """Load sample data from file and send to OpenSearch"""
    try:
        # Read the sample data
        with open(SAMPLE_DATA_FILE, 'r') as f:
            data = json.load(f)
        
        if not isinstance(data, list):
            data = [data]  # Convert to list if it's a single document
        
        print(f"Loaded {len(data)} documents from {SAMPLE_DATA_FILE}")
        
        # Process each document
        success_count = 0
        error_count = 0
        
        for doc in data:
            try:
                # Transform to OCSF format if needed
                ocsf_doc = transform_to_ocsf(doc)
                
                # Determine appropriate index
                index = determine_index(ocsf_doc)
                
                # Generate document ID based on content hash for idempotence
                doc_str = json.dumps(ocsf_doc, sort_keys=True)
                doc_id = hashlib.md5(doc_str.encode()).hexdigest()
                
                # Send to OpenSearch
                response = client.index(
                    index=index,
                    body=ocsf_doc,
                    id=doc_id,
                    refresh=True  # Make document immediately searchable
                )
                
                if response.get('result') in ['created', 'updated']:
                    print(f"Successfully indexed document to {index} with ID: {doc_id}")
                    success_count += 1
                else:
                    print(f"Failed to index document: {response}")
                    error_count += 1
                    
            except Exception as e:
                print(f"Error processing document: {e}")
                error_count += 1
                
        print(f"Indexing completed - Success: {success_count}, Errors: {error_count}")
        
    except FileNotFoundError:
        print(f"Error: Sample data file '{SAMPLE_DATA_FILE}' not found")
        exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {SAMPLE_DATA_FILE}: {e}")
        exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        exit(1)

def main():
    print("=== Starting OpenSearch Data Import ===")
    
    # Save the sample JSON to a file
    sample_data = """[
    {
        "observedTimestamp": "2023-07-21T16:52:08.000Z",
        "http": {
            "response": {
                "status_code": 406,
                "bytes": 6141
            },
            "url": "/strategize",
            "flavor": "1.1",
            "request": {
                "method": "GET"
            },
            "user_agent": {
                "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "name": "Chrome",
                "version": "114.0.0",
                "os": {
                    "name": "Mac OS X",
                    "full": "Mac OS X 10.15.7",
                    "version": "10.15.7",
                    "device": {
                        "name": "Mac"
                    }
                }
            }
        },
        "attributes": {
        "data_stream": {
            "dataset": "apache.access",
            "namespace": "production",
            "type": "logs"
        }
        },
        "event": {
            "result": "success",
            "category": "web",
            "name": "access",
            "type": "access",
            "domain": "apache.access",
            "kind": "event"
        },
        "communication": {
            "source": {
                "address": "127.0.0.1",
                "ip": "42.204.151.42",
                "geo": {
                    "country": "China",
                    "country_iso_code": "CN"
                }
            }
        },
        "body": "15.248.1.132 - - [21/Jun/2023:21:35:24 +0000] \\"GET / HTTP/1.1\\" 403 45 \\"-\\" \\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\\"",
        "traceId": "d09d293a27c9a754f2bf0196b5a1c9bc",
        "spanId": "18ba0e515e42dad0",
        "@timestamp": "2023-07-21T16:52:08.000Z"
    },
    {
        "observedTimestamp": "2023-07-21T16:52:08.000Z",
        "http": {
            "response": {
                "status_code": 406,
                "bytes": 6141
            },
            "url": "/strategize",
            "flavor": "1.1",
            "request": {
                "method": "GET"
            },
            "user_agent": {
                "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "name": "Chrome",
                "version": "114.0.0",
                "os": {
                    "name": "Mac OS X",
                    "full": "Mac OS X 10.15.7",
                    "version": "10.15.7",
                    "device": {
                        "name": "Mac"
                    }
                }
            }
        },
        "attributes": {
        "data_stream": {
            "dataset": "apache.access",
            "namespace": "production",
            "type": "logs"
        }
        },
        "event": {
            "result": "success",
            "category": "web",
            "name": "access",
            "type": "access",
            "domain": "apache.access",
            "kind": "event"
        },
        "communication": {
            "source": {
                "address": "127.0.0.1",
                "ip": "42.204.151.42",
                "geo": {
                    "country": "China",
                    "country_iso_code": "CN"
                }
            }
        },
        "body": "15.248.1.132 - - [21/Jun/2023:21:35:24 +0000] \\"GET / HTTP/1.1\\" 403 45 \\"-\\" \\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\\"",
        "traceId": "d09d293a27c9a754f2bf0196b5a1c9bc",
        "spanId": "18ba0e515e42dad0",
        "@timestamp": "2023-07-21T16:52:08.000Z"
    },
    {
        "observedTimestamp": "2023-07-25T16:52:08.000Z",
        "http": {
            "response": {
                "status_code": 400,
                "bytes": 6141
            },
            "url": "/strategize",
            "flavor": "1.1",
            "request": {
                "method": "GET"
            },
            "user_agent": {
                "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
                "name": "Chrome",
                "version": "114.0.0",
                "os": {
                    "name": "Mac OS X",
                    "full": "Mac OS X 10.15.7",
                    "version": "10.15.7",
                    "device": {
                        "name": "Mac"
                    }
                }
            }
        },
        "attributes": {
            "data_stream": {
                "dataset": "apache.access",
                "namespace": "production",
                "type": "logs"
            }
        },
        "event": {
            "result": "success",
            "category": "web",
            "name": "access",
            "type": "access",
            "domain": "apache.access",
            "kind": "event"
        },
        "communication": {
            "source": {
                "address": "127.0.0.1",
                "ip": "42.204.151.42",
                "geo": {
                    "country": "United States",
                    "country_iso_code": "US"
                }
            }
        },
        "body": "15.248.1.132 - - [21/Jun/2023:21:35:24 +0000] \\"GET / HTTP/1.1\\" 403 45 \\"-\\" \\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36\\"",
        "traceId": "d09d293a27c9a754f2bf0196b5a1c9bc",
        "spanId": "18ba0e515e42dad0",
        "@timestamp": "2023-07-21T16:52:08.000Z"
    },
    {
        "attributes": {
            "data_stream": {
                "dataset": "apache.error",
                "namespace": "production",
                "type": "logs"
            }
        },
        "observedTimestamp": "2023-07-21T16:52:08.000Z",
        "@timestamp": "2023-07-21T16:52:08.000Z",
        "severity": "error",
        "communication": {
            "source": {
                "address": "127.0.0.1",
                "ip": "42.204.151.42",
                "geo": {
                    "country": "France",
                    "country_iso_code": "FR"
                }
            }
        },
        "event": {
            "result": "error",
            "category": "web",
            "name": "error",
            "type": "error",
            "domain": "apache.error",
            "kind": "error"
        },
        "traceId": "d09d293a27c9a754f2bf0196b5a1c9bc",
        "spanId": "18ba0e515e42dad0",
        "body": "[Sat Aug 12 04:05:51 2006] [notice] Apache/1.3.11 (Unix) mod_perl/1.21 configured -- resuming normal operations"
    }
]"""

    # Write sample data to file
    with open(SAMPLE_DATA_FILE, 'w') as f:
        f.write(sample_data)
    
    # Create OpenSearch client
    client = create_opensearch_client()
    
    # Load and send data
    load_and_send_data(client)
    
    print("=== OpenSearch Data Import Complete ===")

if __name__ == "__main__":
    main()