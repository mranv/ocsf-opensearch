#!/usr/bin/env python3

import requests
import json
import time
import hashlib
import argparse
from datetime import datetime
from opensearchpy import OpenSearch, RequestsHttpConnection

# Configuration
DEFAULT_OPENSEARCH_HOST = "localhost"
DEFAULT_OPENSEARCH_PORT = 9200
DEFAULT_OPENSEARCH_USER = "admin"
DEFAULT_OPENSEARCH_PASS = "Anubhav@321"
DEFAULT_OCSF_URL = "https://schema.ocsf.io/sample/1.1.0/classes/network_activity?profiles="
DEFAULT_INDEX = "ocsf-1.1.0-4001-network_activity"
DEFAULT_BATCH_SIZE = 10
DEFAULT_SAMPLES_COUNT = 100 
DEFAULT_DELAY = 0.5  # seconds between API calls

def create_opensearch_client(host, port, username, password, use_ssl=True, verify_certs=False, retry_count=3, file_only_mode=False):
    """Create and configure OpenSearch client"""
    if file_only_mode:
        print("Running in file-only mode. No OpenSearch connection will be established.")
        return None
        
    # Configure connection with timeout
    connection_params = {
        'hosts': [{'host': host, 'port': port}],
        'http_auth': (username, password),
        'use_ssl': use_ssl,
        'verify_certs': verify_certs,
        'ssl_show_warn': False,
        'connection_class': RequestsHttpConnection,
        'timeout': 30,
        'retry_on_timeout': True,
        'max_retries': 3
    }
    
    # Try to connect with retries
    for attempt in range(retry_count):
        try:
            client = OpenSearch(**connection_params)
            # Test connection
            info = client.info()
            print(f"Connected to {info['version']['distribution']} {info['version']['number']}")
            return client
        except Exception as e:
            if attempt < retry_count - 1:
                wait_time = 2 ** attempt  # Exponential backoff
                print(f"Connection attempt {attempt+1}/{retry_count} failed. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                print(f"Failed to connect to OpenSearch after {retry_count} attempts: {e}")
                if file_only_mode:
                    return None
                raise

def fetch_network_activity(url):
    """Fetch a single network activity sample from OCSF schema API"""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from {url}: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON from {url}: {e}")
        return None

def normalize_network_activity(data):
    """Normalize and prepare the network activity data for indexing"""
    # Handle potential structural issues in the OCSF schema API response
    normalized = {}
    
    # Copy original data
    if isinstance(data, dict):
        normalized.update(data)
    else:
        print(f"Unexpected data format: {type(data)}")
        return None
        
    # Ensure timestamp fields
    if '@timestamp' not in normalized:
        timestamp = datetime.utcnow().isoformat() + 'Z'
        normalized['@timestamp'] = timestamp
        
    if 'observedTimestamp' not in normalized:
        normalized['observedTimestamp'] = normalized.get('@timestamp')
    
    # Ensure consistent activity naming
    normalized['activity_id'] = normalized.get('activity_id', 4001)
    normalized['activity_name'] = normalized.get('activity_name', 'Network Activity')
    normalized['class_uid'] = normalized.get('class_uid', '4001')
    normalized['class_name'] = normalized.get('class_name', 'Network Activity')
        
    # Generate IDs if missing
    if 'traceId' not in normalized:
        normalized['traceId'] = hashlib.md5(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
    
    if 'spanId' not in normalized:
        normalized['spanId'] = normalized['traceId'][:16]
    
    return normalized

def save_to_file(data, output_dir, batch_num, index_num):
    """Save a document to a JSON file"""
    if data is None:
        return False
        
    try:
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate a filename
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"{output_dir}/network_activity_batch{batch_num}_doc{index_num}_{timestamp}.json"
        
        # Write the data to file
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
            
        return True
    except Exception as e:
        print(f"Error saving document to file: {e}")
        return False

def index_data(client, data, index, output_dir=None, batch_num=0, index_num=0):
    """Index a single document into OpenSearch or save to file"""
    if data is None:
        return False
    
    # Always save to file if output_dir is provided
    if output_dir:
        file_saved = save_to_file(data, output_dir, batch_num, index_num)
    else:
        file_saved = False
        
    # If no client is provided or client is None, only save to file
    if client is None:
        return file_saved
    
    try:
        # Generate document ID based on content hash for idempotence
        doc_str = json.dumps(data, sort_keys=True)
        doc_id = hashlib.md5(doc_str.encode()).hexdigest()
        
        response = client.index(
            index=index,
            body=data,
            id=doc_id,
            refresh=True  # Make document immediately searchable
        )
        
        return response.get('result') in ['created', 'updated'] or file_saved
    except Exception as e:
        print(f"Error indexing document: {e}")
        # If we saved to file, consider it a partial success
        return file_saved

def fetch_and_index_batch(client, ocsf_url, index, batch_size, delay, output_dir=None, batch_num=0):
    """Fetch and index a batch of network activity samples"""
    success_count = 0
    error_count = 0
    
    for i in range(batch_size):
        try:
            # Fetch data
            raw_data = fetch_network_activity(ocsf_url)
            
            if raw_data:
                # Normalize data
                normalized_data = normalize_network_activity(raw_data)
                
                # Index data
                if normalized_data and index_data(client, normalized_data, index, output_dir, batch_num, i):
                    success_count += 1
                else:
                    error_count += 1
            else:
                error_count += 1
                
            # Add delay between requests to avoid rate limiting
            if i < batch_size - 1:
                time.sleep(delay)
                
        except Exception as e:
            print(f"Error processing document {i} in batch {batch_num}: {e}")
            error_count += 1
            # Continue with next document
    
    return success_count, error_count

def main():
    parser = argparse.ArgumentParser(description='Ingest OCSF network activity data into OpenSearch')
    parser.add_argument('--host', default=DEFAULT_OPENSEARCH_HOST, help='OpenSearch host')
    parser.add_argument('--port', type=int, default=DEFAULT_OPENSEARCH_PORT, help='OpenSearch port')
    parser.add_argument('--user', default=DEFAULT_OPENSEARCH_USER, help='OpenSearch username')
    parser.add_argument('--password', default=DEFAULT_OPENSEARCH_PASS, help='OpenSearch password')
    parser.add_argument('--ssl', action='store_true', help='Use SSL for OpenSearch connection')
    parser.add_argument('--verify-certs', action='store_true', help='Verify SSL certificates')
    parser.add_argument('--url', default=DEFAULT_OCSF_URL, help='OCSF schema API URL')
    parser.add_argument('--index', default=DEFAULT_INDEX, help='OpenSearch index to write to')
    parser.add_argument('--batch-size', type=int, default=DEFAULT_BATCH_SIZE, 
                        help='Number of documents to fetch and index in a batch')
    parser.add_argument('--count', type=int, default=DEFAULT_SAMPLES_COUNT,
                        help='Total number of samples to ingest')
    parser.add_argument('--delay', type=float, default=DEFAULT_DELAY,
                        help='Delay between API requests in seconds')
    parser.add_argument('--continuous', action='store_true',
                        help='Run continuously, ignoring --count')
    parser.add_argument('--output-dir', help='Directory to save JSON files (omit to disable file output)')
    parser.add_argument('--file-only', action='store_true', 
                        help='Only save to files, do not connect to OpenSearch')
    parser.add_argument('--retry-count', type=int, default=3,
                        help='Number of connection retry attempts')
    
    args = parser.parse_args()
    
    # Create output directory if specified
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
    
    print(f"=== Starting OCSF Network Activity Ingestion ===")
    if not args.file_only:
        print(f"Target OpenSearch: {args.host}:{args.port}")
    if args.output_dir:
        print(f"Output directory: {args.output_dir}")
    print(f"Source OCSF API: {args.url}")
    print(f"Target index: {args.index}")
    
    # Create OpenSearch client if not in file-only mode
    client = None
    try:
        client = create_opensearch_client(
            args.host, args.port, args.user, args.password,
            use_ssl=args.ssl, verify_certs=args.verify_certs,
            retry_count=args.retry_count, file_only_mode=args.file_only
        )
    except Exception as e:
        if not args.output_dir:
            print(f"Failed to connect to OpenSearch and no output directory specified. Exiting.")
            return
        print(f"Continuing in file-only mode due to connection error: {e}")
    
    total_success = 0
    total_error = 0
    batches = 0
    
    try:
        if args.continuous:
            print("Running in continuous mode. Press Ctrl+C to stop.")
            while True:
                success, error = fetch_and_index_batch(
                    client, args.url, args.index, args.batch_size, args.delay,
                    output_dir=args.output_dir, batch_num=batches+1
                )
                batches += 1
                total_success += success
                total_error += error
                print(f"Batch {batches} completed - Success: {success}, Errors: {error}, Total indexed: {total_success}")
        else:
            remaining = args.count
            while remaining > 0:
                current_batch = min(remaining, args.batch_size)
                success, error = fetch_and_index_batch(
                    client, args.url, args.index, current_batch, args.delay,
                    output_dir=args.output_dir, batch_num=batches+1
                )
                batches += 1
                total_success += success
                total_error += error
                remaining -= current_batch
                print(f"Batch {batches} completed - Success: {success}, Errors: {error}, " 
                      f"Total indexed: {total_success}, Remaining: {remaining}")
    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        print(f"=== OCSF Network Activity Ingestion Complete ===")
        print(f"Total batches: {batches}")
        print(f"Total success: {total_success}")
        print(f"Total errors: {total_error}")
        if args.output_dir:
            print(f"Output saved to: {args.output_dir}")

# Make sure this module imports properly
import os

if __name__ == "__main__":
    main()