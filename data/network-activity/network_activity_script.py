#!/usr/bin/env python3

import requests
import json
import time
import hashlib
import argparse
import os
import re
import logging
from datetime import datetime, timezone, UTC
from opensearchpy import OpenSearch, RequestsHttpConnection, helpers
from urllib3.exceptions import InsecureRequestWarning
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("network_activity_ingest.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("network_activity_ingest")

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
        logger.info("Running in file-only mode. No OpenSearch connection will be established.")
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
            logger.info(f"Connected to {info['version']['distribution']} {info['version']['number']}")
            return client
        except Exception as e:
            if attempt < retry_count - 1:
                wait_time = 2 ** attempt  # Exponential backoff
                logger.warning(f"Connection attempt {attempt+1}/{retry_count} failed. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error(f"Failed to connect to OpenSearch after {retry_count} attempts: {e}")
                if file_only_mode:
                    return None
                raise

def fetch_network_activity(url, retry_count=3, retry_delay=1):
    """Fetch a single network activity sample from OCSF schema API with retry logic"""
    for attempt in range(retry_count):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            return data
        except requests.exceptions.RequestException as e:
            if attempt < retry_count - 1:
                wait_time = retry_delay * (2 ** attempt)  # Exponential backoff
                logger.warning(f"Request attempt {attempt+1}/{retry_count} failed. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                logger.error(f"Error fetching data from {url}: {e}")
                return None
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON from {url}: {e}")
            return None

def normalize_network_activity(data):
    """Normalize and prepare the network activity data for indexing"""
    # Handle potential structural issues in the OCSF schema API response
    normalized = {}
    
    # Copy original data
    if isinstance(data, dict):
        normalized.update(data)
    else:
        logger.error(f"Unexpected data format: {type(data)}")
        return None
        
    # Ensure timestamp fields
    if '@timestamp' not in normalized:
        timestamp = datetime.now(UTC).isoformat()
        normalized['@timestamp'] = timestamp
        
    if 'observedTimestamp' not in normalized:
        normalized['observedTimestamp'] = normalized.get('@timestamp')
    
    # Fix metadata fields
    if 'metadata' in normalized:
        # Handle non-date original_time in metadata
        if 'original_time' in normalized['metadata']:
            orig_time = normalized['metadata']['original_time']
            # If it's not a proper timestamp, replace it
            if not isinstance(orig_time, (int, float)) and not re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', str(orig_time)):
                # Remove the field or replace with current time
                normalized['metadata']['original_time'] = normalized.get('@timestamp')
    
    # Fix time fields that should be dates
    time_fields = [
        'start_time', 'end_time', 'create_time', 'update_time', 
        'detect_time', 'first_seen', 'last_seen', 'time'
    ]
    
    for field in time_fields:
        if field in normalized:
            value = normalized[field]
            # If it's a timestamp (epoch) as number, convert to ISO format
            if isinstance(value, (int, float)) and value > 1000000000:  # Likely a unix timestamp
                try:
                    normalized[field] = datetime.fromtimestamp(value/1000, UTC).isoformat()
                except (ValueError, OverflowError):
                    normalized[field] = normalized.get('@timestamp')
            # If it's a string but not ISO format, replace
            elif not isinstance(value, (int, float)) and not re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', str(value)):
                normalized[field] = normalized.get('@timestamp')
    
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
        logger.error(f"Error saving document to file: {e}")
        return False

def upload_bulk(client, bulk_data):
    """Upload data in bulk to OpenSearch"""
    try:
        # Use the helpers.bulk API for efficient uploading
        success, errors = helpers.bulk(client, bulk_data, stats_only=True)
        if errors:
            logger.warning(f"Encountered {errors} errors during bulk upload")
        return success, errors
    except Exception as e:
        logger.error(f"Bulk upload failed: {e}")
        return 0, len(bulk_data)

def process_and_upload_batch(client, normalized_data_list, index, output_dir=None, batch_num=0):
    """Process and upload a batch of normalized data"""
    if not normalized_data_list:
        return 0, 0
        
    success_count = 0
    error_count = 0
    
    # If we're in file-only mode
    if client is None and output_dir:
        for i, data in enumerate(normalized_data_list):
            if save_to_file(data, output_dir, batch_num, i):
                success_count += 1
            else:
                error_count += 1
        return success_count, error_count
    
    # Prepare bulk upload data
    bulk_data = []
    file_save_results = []
    
    for i, data in enumerate(normalized_data_list):
        # Save to file if output directory is specified
        if output_dir:
            file_saved = save_to_file(data, output_dir, batch_num, i)
            file_save_results.append(file_saved)
        
        # Generate document ID based on content hash for idempotence
        doc_str = json.dumps(data, sort_keys=True)
        doc_id = hashlib.md5(doc_str.encode()).hexdigest()
        
        # Add to bulk upload list
        bulk_data.append({
            '_index': index,
            '_id': doc_id,
            '_source': data
        })
    
    # Upload to OpenSearch
    if bulk_data and client is not None:
        success, errors = upload_bulk(client, bulk_data)
        success_count += success
        error_count += errors
    elif output_dir:
        # If we're only saving to files, count successes from file operations
        success_count = sum(1 for result in file_save_results if result)
        error_count = len(file_save_results) - success_count
    
    return success_count, error_count

def fetch_and_index_batch(client, ocsf_url, index, batch_size, delay, output_dir=None, batch_num=0):
    """Fetch and index a batch of network activity samples"""
    normalized_data_list = []
    fetch_errors = 0
    
    for i in range(batch_size):
        try:
            # Fetch data
            raw_data = fetch_network_activity(ocsf_url)
            
            if raw_data:
                # Normalize data
                normalized_data = normalize_network_activity(raw_data)
                if normalized_data:
                    normalized_data_list.append(normalized_data)
                else:
                    fetch_errors += 1
            else:
                fetch_errors += 1
                
            # Add delay between requests to avoid rate limiting
            if i < batch_size - 1:
                time.sleep(delay)
                
        except Exception as e:
            logger.error(f"Error processing document {i} in batch {batch_num}: {e}")
            fetch_errors += 1
            # Continue with next document
    
    # Process and upload the batch
    if normalized_data_list:
        success_count, error_count = process_and_upload_batch(
            client, normalized_data_list, index, output_dir, batch_num
        )
        return success_count, error_count + fetch_errors
    else:
        return 0, fetch_errors

def upload_from_directory(client, input_dir, index):
    """Upload all JSON files from a directory to OpenSearch"""
    logger.info(f"Uploading files from {input_dir}")
    
    # Find all JSON files
    file_pattern = os.path.join(input_dir, "*.json")
    json_files = sorted(os.path.join(input_dir, f) for f in os.listdir(input_dir) if f.endswith('.json'))
    
    if not json_files:
        logger.warning(f"No JSON files found in {input_dir}")
        return 0, 0
        
    logger.info(f"Found {len(json_files)} JSON files to process")
    
    success_count = 0
    error_count = 0
    bulk_data = []
    bulk_size = 50  # Process in batches of 50
    
    # Process each file
    for i, file_path in enumerate(json_files):
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Normalize/fix the data
            normalized_data = normalize_network_activity(data)
            
            if normalized_data:
                # Generate document ID based on content hash for idempotence
                doc_str = json.dumps(normalized_data, sort_keys=True)
                doc_id = hashlib.md5(doc_str.encode()).hexdigest()
                
                # Add to bulk upload list
                bulk_data.append({
                    '_index': index,
                    '_id': doc_id,
                    '_source': normalized_data
                })
                
                # Upload in batches
                if len(bulk_data) >= bulk_size:
                    success, errors = upload_bulk(client, bulk_data)
                    success_count += success
                    error_count += errors
                    bulk_data = []
                    logger.info(f"Processed {i+1}/{len(json_files)} files - Current success rate: {success_count/(success_count+error_count)*100:.1f}%")
            else:
                logger.warning(f"Could not normalize data from {file_path}")
                error_count += 1
                
        except Exception as e:
            logger.error(f"Error processing {file_path}: {e}")
            error_count += 1
    
    # Upload any remaining documents
    if bulk_data:
        success, errors = upload_bulk(client, bulk_data)
        success_count += success
        error_count += errors
    
    return success_count, error_count

def check_index_exists(client, index_name):
    """Check if an index exists and create it if it doesn't"""
    try:
        exists = client.indices.exists(index=index_name)
        if not exists:
            logger.info(f"Index {index_name} doesn't exist. Creating...")
            # Create a basic index with appropriate mappings
            mappings = {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "observedTimestamp": {"type": "date"},
                        "start_time": {"type": "date"},
                        "end_time": {"type": "date"},
                        "create_time": {"type": "date"},
                        "update_time": {"type": "date"},
                        "detect_time": {"type": "date"},
                        "first_seen": {"type": "date"},
                        "last_seen": {"type": "date"},
                        "time": {"type": "date"},
                        "activity_id": {"type": "integer"},
                        "class_uid": {"type": "keyword"},
                        "severity_id": {"type": "integer"},
                        "traceId": {"type": "keyword"},
                        "spanId": {"type": "keyword"},
                        "metadata": {
                            "type": "object",
                            "properties": {
                                "original_time": {"type": "date"}
                            }
                        }
                    }
                }
            }
            client.indices.create(index=index_name, body=mappings)
            logger.info(f"Index {index_name} created successfully")
            return True
        return True
    except Exception as e:
        logger.error(f"Error checking/creating index {index_name}: {e}")
        return False

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
    parser.add_argument('--input-dir', help='Upload existing JSON files from directory')
    parser.add_argument('--log-level', default='INFO', 
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set logging level')
    
    args = parser.parse_args()
    
    # Set log level
    logger.setLevel(getattr(logging, args.log_level))
    
    # Create output directory if specified
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
    
    logger.info(f"=== Starting OCSF Network Activity Ingestion ===")
    if not args.file_only:
        logger.info(f"Target OpenSearch: {args.host}:{args.port}")
    if args.output_dir:
        logger.info(f"Output directory: {args.output_dir}")
    if args.input_dir:
        logger.info(f"Input directory: {args.input_dir}")
    else:
        logger.info(f"Source OCSF API: {args.url}")
    logger.info(f"Target index: {args.index}")
    
    # Create OpenSearch client if not in file-only mode
    client = None
    try:
        if not args.file_only:
            client = create_opensearch_client(
                args.host, args.port, args.user, args.password,
                use_ssl=args.ssl, verify_certs=args.verify_certs,
                retry_count=args.retry_count, file_only_mode=args.file_only
            )
            
            # Check if index exists and create it if needed
            if client and not check_index_exists(client, args.index):
                if not args.output_dir:
                    logger.error("Failed to create index and no output directory specified. Exiting.")
                    return
                logger.warning("Continuing in file-only mode due to index creation failure")
                client = None
                args.file_only = True
    except Exception as e:
        if not args.output_dir and not args.input_dir:
            logger.error(f"Failed to connect to OpenSearch and no output/input directory specified. Exiting.")
            return
        logger.warning(f"Continuing in file-only mode due to connection error: {e}")
        client = None
        args.file_only = True
    
    # Handle uploading from directory
    if args.input_dir:
        if client:
            success_count, error_count = upload_from_directory(client, args.input_dir, args.index)
            logger.info(f"=== Upload from directory complete ===")
            logger.info(f"Total successful: {success_count}")
            logger.info(f"Total errors: {error_count}")
        else:
            logger.error("Cannot upload from directory without OpenSearch connection")
        return
    
    # Handle fetching and indexing
    total_success = 0
    total_error = 0
    batches = 0
    
    try:
        if args.continuous:
            logger.info("Running in continuous mode. Press Ctrl+C to stop.")
            while True:
                success, error = fetch_and_index_batch(
                    client, args.url, args.index, args.batch_size, args.delay,
                    output_dir=args.output_dir, batch_num=batches+1
                )
                batches += 1
                total_success += success
                total_error += error
                logger.info(f"Batch {batches} completed - Success: {success}, Errors: {error}, Total indexed: {total_success}")
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
                logger.info(f"Batch {batches} completed - Success: {success}, Errors: {error}, " 
                      f"Total indexed: {total_success}, Remaining: {remaining}")
    except KeyboardInterrupt:
        logger.info("\nOperation interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
    finally:
        logger.info(f"=== OCSF Network Activity Ingestion Complete ===")
        logger.info(f"Total batches: {batches}")
        logger.info(f"Total success: {total_success}")
        logger.info(f"Total errors: {total_error}")
        if args.output_dir:
            logger.info(f"Output saved to: {args.output_dir}")

if __name__ == "__main__":
    main()